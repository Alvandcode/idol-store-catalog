"""GitHub API client with SSRF protection, rate-limit handling and size-capped downloads.

Security rules enforced here:
- Only github.com / api.github.com URLs are ever requested (validated host).
- Redirect targets are re-validated; redirect count is capped.
- Every download is size-capped; nothing is written to disk until hashed.
- The GitHub token is used only in Authorization headers, never in reports.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from . import USER_AGENT
from .config import DOWNLOAD_TIMEOUT_SECONDS, HTTP_RETRIES, MAX_REDIRECTS

_ALLOWED_HOSTS = {"github.com", "www.github.com", "api.github.com", "objects.githubusercontent.com", "raw.githubusercontent.com", "codeload.github.com"}
_CHUNK = 1024 * 1024


class GitHubError(RuntimeError):
    pass


class RateLimitError(GitHubError):
    pass


class SSRFBlocked(GitHubError):
    pass


def validate_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("https",):
        raise SSRFBlocked(f"Non-HTTPS URL blocked: {url[:120]}")
    host = (parsed.hostname or "").lower()
    if host not in _ALLOWED_HOSTS:
        raise SSRFBlocked(f"Host not allowed: {host}")
    return url


def repo_ref(value: str) -> str:
    """Accept 'owner/repo' or full GitHub URL; return 'owner/repo'.

    The returned value is validated against the owner/repo grammar so it can
    only ever be used as a URL path segment, never as a shell command.
    """
    value = str(value).strip().rstrip("/")
    if value.lower().startswith(("http://", "https://")) or "github.com" in value.split("/")[0]:
        parsed = urllib.parse.urlparse(value if "://" in value else "https://" + value)
        if (parsed.hostname or "").lower() != "github.com":
            raise SSRFBlocked("Only github.com repositories are supported")
        parts = [p for p in parsed.path.split("/") if p and p not in ("tree", "releases", "tag")]
    else:
        parts = [p for p in value.split("/") if p]
    if len(parts) >= 2:
        candidate = f"{parts[0]}/{parts[1]}"
        if candidate.endswith(".git"):
            candidate = candidate[: -len(".git")]
        import re

        if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", candidate):
            return candidate
    raise GitHubError(f"Unsupported GitHub repository reference: {value[:120]}")


class GitHubClient:
    def __init__(self, token: str | None = None):
        self.token = token or ""
        self.calls = 0

    def _headers(self, binary: bool) -> dict:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/octet-stream" if binary else "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _open(self, url: str, binary: bool):
        validate_url(url)
        req = urllib.request.Request(url, headers=self._headers(binary))
        opener = urllib.request.build_opener(_SafeRedirectHandler())
        return opener.open(req, timeout=DOWNLOAD_TIMEOUT_SECONDS)

    def request(self, url: str, *, binary: bool = False, max_bytes: int | None = None) -> bytes:
        last_error: Exception | None = None
        for attempt in range(HTTP_RETRIES + 1):
            try:
                with self._open(url, binary) as response:
                    data = bytearray()
                    while True:
                        part = response.read(_CHUNK)
                        if not part:
                            break
                        data.extend(part)
                        if max_bytes is not None and len(data) > max_bytes:
                            raise GitHubError(f"Download exceeded limit of {max_bytes} bytes")
                    return bytes(data)
            except urllib.error.HTTPError as exc:
                if exc.code == 403 and exc.headers.get("X-RateLimit-Remaining") == "0":
                    reset = exc.headers.get("X-RateLimit-Reset")
                    wait = max(0, int(reset) - int(time.time()) + 1) if reset else 60
                    raise RateLimitError(f"GitHub API rate limit hit; resets in ~{wait}s") from exc
                if exc.code in (500, 502, 503, 504) and attempt < HTTP_RETRIES:
                    time.sleep(2 * (attempt + 1))
                    last_error = exc
                    continue
                raise GitHubError(f"HTTP {exc.code} for {url[:120]}") from exc
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if attempt < HTTP_RETRIES:
                    time.sleep(2 * (attempt + 1))
                    last_error = exc
                    continue
                raise GitHubError(f"Network error for {url[:120]}: {exc}") from exc
        raise GitHubError(f"Request failed: {url[:120]}") from last_error

    def api_json(self, path: str) -> Any:
        """path is an API path such as '/repos/owner/repo/releases'."""
        self.calls += 1
        url = f"https://api.github.com{path}"
        return json.loads(self.request(url).decode("utf-8"))

    def download(self, url: str, max_bytes: int) -> bytes:
        return self.request(url, binary=True, max_bytes=max_bytes)


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Cap redirects; every redirect target is validated by GitHubClient._open."""

    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        count = getattr(req, "_idol_redirect_count", 0)
        if count >= self.max_redirections:
            raise GitHubError("Too many redirects")
        req._idol_redirect_count = count + 1  # type: ignore[attr-defined]
        return urllib.request.HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, headers, newurl)
