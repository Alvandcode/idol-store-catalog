"""Per-application scanning pipeline.

Flow per app (section 4 modules):
  Collector (GitHub API) -> Source download + safe extraction -> engines
  -> Asset downloads (hash first, engines) -> Risk Engine -> Report entry.

Guarantees:
- Downloaded files are NEVER executed.
- Every asset hash is re-verified after scanning (integrity change check).
- Scans run with bounded parallelism and hard limits.
"""
from __future__ import annotations

import fnmatch
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from . import SCANNER_VERSION, models
from .cache import ResultCache, cache_key
from .config import AppConfig
from .engines import binary_inspect, clamav, gitleaks, osv, semgrep, yara
from .extractor import UnsafeArchive, extract_zip_source, find_source_root
from .false_positives import FalsePositiveRegistry
from .github_client import GitHubClient, GitHubError
from .risk_engine import evaluate
from .util import now_iso, safe_filename, sha256_bytes, sha256_file

_ASSET_SCAN_EXTS = (".apk", ".exe", ".zip", ".msi", ".jar", ".dex", ".so", ".aar", ".7z", ".tar", ".gz", ".tgz", ".bin", ".ipa", ".whl")


def scan_app(
    app: dict[str, Any],
    client: GitHubClient,
    config: AppConfig,
    rules_dir: Path,
    cache: ResultCache,
    fp_registry: FalsePositiveRegistry,
    community_rules_dir: Path | None = None,
) -> dict[str, Any]:
    app_id = str(app.get("id") or app.get("name") or "unknown")
    entry: dict[str, Any] = {
        "id": app_id,
        "name": app.get("name"),
        "github_repository": str(app.get("github") or ""),
        "scan_timestamp": now_iso(),
        "scanner_version": SCANNER_VERSION,
        "from_cache": False,
        "release_version": None,
        "release_date": None,
        "overall_status": models.NOT_SCANNED,
        "risk_level": "unknown",
        "source_scan": None,
        "scanned_assets": [],
        "detections": [],
        "vulnerabilities": [],
        "warnings": [],
        "scan_errors": [],
        "skipped_files": [],
        "execution_statistics": {"api_calls": 0, "downloaded_bytes": 0, "duration_note": "single-run"},
    }
    repo: str
    try:
        from .github_client import repo_ref

        repo = repo_ref(entry["github_repository"])
        repo_data = client.api_json(f"/repos/{repo}")
        releases = client.api_json(f"/repos/{repo}/releases?per_page=20")
        stable = next((r for r in releases if not r.get("draft") and not r.get("prerelease")), None)
        if not stable:
            entry["overall_status"] = models.NOT_SCANNED
            entry["warnings"].append({"key": "warning.no_stable_release"})
            return _finalize(entry)
        tag = str(stable.get("tag_name", ""))
        entry["release_version"] = tag
        entry["release_date"] = stable.get("published_at")
    except GitHubError as exc:
        entry["overall_status"] = models.SCAN_ERROR
        entry["scan_errors"].append(str(exc)[:500])
        return _finalize(entry)

    # ---- cache lookup keyed on release source archive + asset identifiers ----
    asset_ids = [a.get("browser_download_url", "") for a in stable.get("assets", [])]
    key = cache_key(tag, entry["github_repository"], *asset_ids)
    cached = cache.load(app_id, key)
    if cached and cached.get("release_version") == tag:
        entry.update({k: cached[k] for k in cached if k not in ("from_cache", "cache_key", "scanner_version", "policy_key")})
        entry["from_cache"] = True
        entry["scan_timestamp"] = now_iso()
        entry["execution_statistics"]["cache_hit"] = True
        return _finalize(entry)

    try:
        with tempfile.TemporaryDirectory(prefix="idol-scan-v2-") as tmp:
            root = Path(tmp)
            _scan_sources(entry, repo, tag, stable, root, client, config, rules_dir, community_rules_dir)
            _scan_assets(entry, stable, root, client, config, rules_dir, fp_registry, community_rules_dir)
    except (UnsafeArchive, GitHubError) as exc:
        entry["scan_errors"].append(str(exc)[:500])
    except Exception as exc:  # defensive: one app must never break the run
        entry["scan_errors"].append(f"unexpected: {type(exc).__name__}: {exc}"[:500])

    entry["execution_statistics"]["api_calls"] = client.calls
    status, risk, blocking, warnings = evaluate(
        source_scan=entry["source_scan"] or {},
        scanned_assets=entry["scanned_assets"],
        had_release=True,
        technical_error=None,
    )
    if entry["scan_errors"]:
        status = models.SCAN_ERROR
    # Unavailable/skipped required components are scan errors, not clean notes.
    if status == models.INCOMPLETE:
        entry["scan_errors"].extend(warnings)
        warnings = []
    entry["overall_status"] = status
    entry["risk_level"] = risk
    entry["blocking_evidence"] = blocking
    entry["warnings"].extend(warnings)
    entry["status"] = models.v1_status(status)  # v1 compatibility field

    # Collect top-level detections/vulnerabilities lists for the report.
    src = entry["source_scan"] or {}
    entry["detections"].extend(src.get("detections", []))
    entry["vulnerabilities"].extend((src.get("dependency") or {}).get("vulnerabilities", []))

    store = {k: entry[k] for k in entry if k not in ("from_cache",)}
    store["release_version"] = entry["release_version"]
    cache.store(app_id, key, store)
    return _finalize(entry)


def _scan_sources(
    entry: dict[str, Any], repo: str, tag: str, stable: dict[str, Any],
    root: Path, client: GitHubClient, config: AppConfig, rules_dir: Path,
    community_rules_dir: Path | None,
) -> None:
    archive_url = f"https://codeload.github.com/{repo}/legacy.zip/refs/tags/{tag}"
    try:
        archive = client.download(archive_url, config.max_source_bytes)
    except GitHubError:
        archive = client.download(f"https://api.github.com/repos/{repo}/zipball/{tag}", config.max_source_bytes)
    entry["source_scan"] = {"sha256_source_archive": sha256_bytes(archive), "archive_bytes": len(archive)}
    try:
        source_dir = find_source_root(extract_zip_source(archive, root / "source", max_files=config.max_source_files))
    except UnsafeArchive as exc:
        entry["scan_errors"].append(str(exc)[:300])
        entry["source_scan"]["status"] = "extraction_rejected"
        return
    entry["source_scan"]["clamav"] = clamav.scan(source_dir)
    entry["source_scan"]["dependency"] = osv.scan(source_dir)
    entry["source_scan"]["yara"] = yara.scan(source_dir, rules_dir, community_rules_dir)
    entry["source_scan"]["semgrep"] = semgrep.scan(source_dir, rules_dir)
    entry["source_scan"]["gitleaks"] = gitleaks.scan(source_dir)


def _scan_assets(
    entry: dict[str, Any], stable: dict[str, Any], root: Path,
    client: GitHubClient, config: AppConfig, rules_dir: Path,
    fp_registry: FalsePositiveRegistry, community_rules_dir: Path | None = None,
) -> None:
    assets = [a for a in stable.get("assets", []) if not _skip(a, config)]
    if not assets:
        entry["warnings"].append({"key": "warning.no_supported_assets"})
        return

    def scan_one(asset: dict[str, Any]) -> dict[str, Any]:
        name = str(asset.get("name") or "asset")
        size = int(asset.get("size") or 0)
        item: dict[str, Any] = {"name": name, "declared_size": size}
        url = asset.get("browser_download_url", "")
        if size > config.max_asset_bytes:
            item.update({"status": "not_scanned_size_limit", "sha256": None})
            return item
        try:
            data = client.download(url, config.max_asset_bytes)
        except GitHubError as exc:
            item.update({"status": "download_or_scan_error", "error": str(exc)[:400], "sha256": None})
            return item
        path = root / "assets" / safe_filename(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        item["sha256"] = sha256_bytes(data)
        item["size"] = len(data)
        binary = binary_inspect.inspect(path, pre_hash=item["sha256"])
        # Integrity: re-hash after the whole scan chain below.
        if binary["status"] == "corrupt_archive":
            item["status"] = "download_or_scan_error"
            item["error"] = "archive corrupt or unreadable"
            item["binary"] = binary
            return item
        cl = clamav.scan(path)
        yr = yara.scan(path, rules_dir, community_rules_dir)
        item["binary"] = binary
        item["clamav"] = cl
        item["yara"] = yr
        post_hash = sha256_file(path)
        item["sha256_after_scan"] = post_hash
        item["integrity_verified"] = post_hash == item["sha256"]
        review = fp_registry.lookup(item["sha256"])
        if review:
            item["manual_review"] = review
        # Asset-level v1-compatible status:
        if cl.get("status") == "detection":
            item["status"] = "malware_detected"
        elif any(d.get("severity") == "critical" for d in yr.get("detections", [])):
            item["status"] = "malware_detected"
        elif yr.get("detections") or binary.get("flags"):
            item["status"] = "suspicious_content"
        elif not item["integrity_verified"]:
            item["status"] = "download_or_scan_error"
            item["error"] = "file changed during scanning"
        else:
            item["status"] = "no_detection"
        return item

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(scan_one, assets))
    entry["scanned_assets"].extend(results)
    for a in stable.get("assets", []):
        if _skip(a, config):
            entry["skipped_files"].append({"name": a.get("name"), "reason": "unsupported_file_type", "reason_key": "skip.unsupported_file_type"})


def _skip(asset: dict[str, Any], config: AppConfig) -> bool:
    name = str(asset.get("name") or "")
    if not name.lower().endswith(_ASSET_SCAN_EXTS):
        return True
    return any(fnmatch.fnmatch(name, pat) for pat in config.skip_asset_globs)


def _finalize(entry: dict[str, Any]) -> dict[str, Any]:
    entry.setdefault("status", models.v1_status(entry.get("overall_status", models.SCAN_ERROR)))
    return entry
