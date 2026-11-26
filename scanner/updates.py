"""Automatic signature/rule updates from free, open-source feeds.

Three independent update layers (documented in SECURITY-SCANNER.md):
1. ClamAV signature DB — `freshclam` runs on every CI pass (incremental).
2. Community YARA rules — curated open-source rule sets downloaded on each
   scheduled run, cached, and merged into scanning with severity capped at
   "medium" (community rules request review; they never auto-convict).
3. OSV — inherently live (queries the OSV.dev API at scan time).

Only HTTPS GitHub-hosted sources are used (validated by github_client), so
no files are ever sent to external services and no paid feeds are involved.
"""
from __future__ import annotations

import argparse
import io
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import USER_AGENT
from .extractor import UnsafeArchive, safe_target
from .github_client import GitHubClient, GitHubError
from .util import atomic_write_json, now_iso, sha256_bytes

MAX_SOURCE_ZIP_BYTES = 150 * 1024 * 1024
MAX_RULE_FILES = 800
MAX_RULE_FILE_BYTES = 3 * 1024 * 1024
MAX_TOTAL_RULE_BYTES = 40 * 1024 * 1024

SOURCES: list[dict[str, str]] = [
    {
        "name": "yara-rules-rules",
        "repo": "Yara-Rules/rules",
        "url": "https://codeload.github.com/Yara-Rules/rules/legacy.zip/refs/heads/master",
        "license": "LGPL-3.0",
    },
    {
        "name": "signature-base",
        "repo": "Neo23x0/signature-base",
        "url": "https://codeload.github.com/Neo23x0/signature-base/legacy.zip/refs/heads/master",
        "license": "custom open license (attribution)",
    },
]


def update_community_rules(out_dir: Path, manifest_path: Path, client: GitHubClient | None = None) -> dict[str, Any]:
    """Refresh community YARA rules. Never raises: on failure the previous
    rules stay in place and the manifest records the failure."""
    client = client or GitHubClient()
    manifest: dict[str, Any] = {"updatedAt": now_iso(), "sources": []}
    out_dir.mkdir(parents=True, exist_ok=True)
    total_bytes = 0
    for source in SOURCES:
        entry: dict[str, Any] = {
            "name": source["name"], "repo": source["repo"],
            "license": source["license"], "updatedAt": now_iso(),
        }
        try:
            archive = client.download(source["url"], MAX_SOURCE_ZIP_BYTES)
        except (GitHubError, Exception) as exc:  # keep previous rules on any failure
            entry.update({"status": "kept_previous", "error": str(exc)[:300]})
            manifest["sources"].append(entry)
            continue
        entry["archive_sha256"] = sha256_bytes(archive)
        files, skipped = _extract_yar_files(
            archive, out_dir, prefix=source["name"] + "__", source_name=source["name"],
        )
        entry.update({"status": "updated", "files": len(files), "skipped_rule_files": skipped})
        total_bytes += sum(files.values())
        manifest["sources"].append(entry)
    manifest["totalRuleFiles"] = sum(
        s.get("files", 0) for s in manifest["sources"]
    )
    manifest["totalRuleBytes"] = total_bytes
    atomic_write_json(manifest_path, manifest)
    return manifest


def _extract_yar_files(archive: bytes, out_dir: Path, *, prefix: str, source_name: str) -> tuple[dict[str, int], list[str]]:
    """Extract only *.yar entries, with traversal/symlink/size guards."""
    files: dict[str, int] = {}
    skipped: list[str] = []
    extracted_bytes = 0
    if not zipfile.is_zipfile(io.BytesIO(archive)):
        return files, [f"{source_name}: archive is not a valid zip"]
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        for info in z.infolist():
            name = info.filename
            if not name.lower().endswith(".yar") or info.is_dir():
                continue
            if any(part == ".." for part in Path(name).parts):
                skipped.append(f"{name}: unsafe path rejected")
                continue
            if len(files) >= MAX_RULE_FILES:
                skipped.append(f"{name}: file-count cap reached")
                continue
            if info.file_size > MAX_RULE_FILE_BYTES:
                skipped.append(f"{name}: exceeds per-file size cap")
                continue
            if extracted_bytes + info.file_size > MAX_TOTAL_RULE_BYTES:
                skipped.append(f"{name}: total size cap reached")
                continue
            try:
                target = safe_target(out_dir, prefix + name.replace("/", "_"))
            except UnsafeArchive:
                skipped.append(f"{name}: unsafe path rejected")
                continue
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                skipped.append(f"{name}: symlink rejected")
                continue
            try:
                with z.open(info) as src, target.open("wb") as dst:
                    dst.write(src.read(MAX_RULE_FILE_BYTES + 1))
            except (OSError, zipfile.BadZipFile) as exc:
                skipped.append(f"{name}: {str(exc)[:120]}")
                continue
            total_bytes_local = target.stat().st_size
            extracted_bytes += total_bytes_local
            files[target.name] = total_bytes_local
    return files, skipped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scanner.updates")
    parser.add_argument("--out-dir", default="security-cache/yara-community")
    parser.add_argument("--manifest", default="security-cache/yara-sources.json")
    args = parser.parse_args(argv)
    manifest = update_community_rules(Path(args.out_dir), Path(args.manifest))
    print(f"Community YARA update: {manifest.get('totalRuleFiles', 0)} rule files from "
          f"{len(SOURCES)} sources -> {args.out_dir}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
