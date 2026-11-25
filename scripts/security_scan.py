#!/usr/bin/env python3
"""Scan Idol Store catalog repositories and their latest stable release assets.

This script downloads source archives and release assets but NEVER executes them.
It writes a machine-readable security-results.json report.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

API = "https://api.github.com"
USER_AGENT = "Idol-Store-Security-Scanner/1.0"
CHUNK = 1024 * 1024


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def github_request(url: str, *, binary: bool = False, max_bytes: int | None = None) -> bytes:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json" if not binary else "application/octet-stream",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=90) as response:
        data = bytearray()
        while True:
            part = response.read(CHUNK)
            if not part:
                break
            data.extend(part)
            if max_bytes is not None and len(data) > max_bytes:
                raise ValueError(f"Download exceeded configured limit ({max_bytes} bytes)")
        return bytes(data)


def api_json(url: str) -> Any:
    return json.loads(github_request(url).decode("utf-8"))


def repo_name(value: str) -> str:
    value = value.strip()
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        return value
    parsed = urllib.parse.urlparse(value if "://" in value else "https://" + value)
    if parsed.hostname and parsed.hostname.lower() == "github.com":
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1].removesuffix('.git')}"
    raise ValueError(f"Unsupported GitHub repository reference: {value}")


def safe_extract_zip(data: bytes, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(__import__("io").BytesIO(data)) as archive:
        root = destination.resolve()
        for info in archive.infolist():
            target = (destination / info.filename).resolve()
            if target != root and root not in target.parents:
                raise ValueError("Unsafe path detected in source archive")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst)


def run_tool(command: list[str], *, cwd: Path | None = None) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            command, cwd=str(cwd) if cwd else None,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=45 * 60, check=False,
        )
        return {"available": True, "exitCode": proc.returncode, "output": proc.stdout[-12000:]}
    except FileNotFoundError:
        return {"available": False, "exitCode": None, "output": "Scanner executable not installed"}
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return {"available": True, "exitCode": 124, "output": (output + "\nTimed out")[-12000:]}


def clam_scan(path: Path) -> dict[str, Any]:
    result = run_tool(["clamscan", "--recursive", "--infected", "--no-summary", str(path)])
    output = result["output"]
    detections = [line for line in output.splitlines() if line.strip().endswith(" FOUND")]
    result["detections"] = detections[:100]
    if not result["available"]:
        result["status"] = "scanner_unavailable"
    elif result["exitCode"] == 0:
        result["status"] = "no_detection"
    elif result["exitCode"] == 1:
        result["status"] = "detection"
    else:
        result["status"] = "scan_error"
    result.pop("output", None)
    return result


def osv_scan(path: Path) -> dict[str, Any]:
    result = run_tool(["osv-scanner", "scan", "source", "-r", str(path), "--format", "json"])
    output = result.pop("output", "")
    parsed = None
    try:
        start = output.find("{")
        if start >= 0:
            parsed = json.loads(output[start:])
    except json.JSONDecodeError:
        pass
    result["report"] = parsed
    if not result["available"]:
        result["status"] = "scanner_unavailable"
    elif result["exitCode"] == 0:
        result["status"] = "no_known_vulnerabilities"
    elif result["exitCode"] == 1:
        result["status"] = "vulnerabilities_found"
    else:
        result["status"] = "scan_error"
        result["details"] = output[-4000:]
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_app(app: dict[str, Any], max_asset_bytes: int, max_source_bytes: int) -> dict[str, Any]:
    app_id = str(app.get("id") or app.get("name") or "unknown")
    raw_repo = str(app.get("github") or "")
    result: dict[str, Any] = {
        "id": app_id,
        "name": app.get("name"),
        "repository": raw_repo,
        "scannedAt": now_iso(),
        "release": None,
        "source": None,
        "assets": [],
        "status": "scan_error",
        "notes": [],
    }
    try:
        repo = repo_name(raw_repo)
        repo_data = api_json(f"{API}/repos/{repo}")
        releases = api_json(f"{API}/repos/{repo}/releases?per_page=30")
        stable = next((r for r in releases if not r.get("draft") and not r.get("prerelease")), None)
        if not stable:
            result["status"] = "no_stable_release"
            result["notes"].append("No stable GitHub Release was found.")
            return result

        tag = stable.get("tag_name", "")
        result["release"] = {
            "tag": tag,
            "publishedAt": stable.get("published_at"),
            "url": stable.get("html_url"),
        }

        with tempfile.TemporaryDirectory(prefix="idol-scan-") as temp:
            root = Path(temp)
            source_dir = root / "source"
            archive_url = f"{API}/repos/{repo}/zipball/{urllib.parse.quote(tag, safe='')}"
            archive = github_request(archive_url, binary=True, max_bytes=max_source_bytes)
            safe_extract_zip(archive, source_dir)
            source_scan = clam_scan(source_dir)
            source_scan["dependencyAudit"] = osv_scan(source_dir)
            result["source"] = source_scan

            for asset in stable.get("assets", []):
                name = str(asset.get("name") or "asset")
                size = int(asset.get("size") or 0)
                item: dict[str, Any] = {"name": name, "size": size}
                if size > max_asset_bytes:
                    item.update({"status": "not_scanned_size_limit", "sha256": None})
                    result["assets"].append(item)
                    result["notes"].append(f"{name}: exceeded configured asset size limit.")
                    continue
                try:
                    data = github_request(asset["browser_download_url"], binary=True, max_bytes=max_asset_bytes)
                    file_path = root / ("asset-" + re.sub(r"[^A-Za-z0-9._-]", "_", name))
                    file_path.write_bytes(data)
                    item["sha256"] = sha256_file(file_path)
                    item["size"] = len(data)
                    item["clamav"] = clam_scan(file_path)
                    if item["clamav"]["status"] == "detection":
                        item["status"] = "malware_detected"
                    elif item["clamav"]["status"] == "no_detection":
                        item["status"] = "no_detection"
                    else:
                        item["status"] = "scan_error"
                except Exception as exc:
                    item.update({"status": "download_or_scan_error", "error": str(exc)[:500], "sha256": None})
                result["assets"].append(item)

        source_status = result["source"]["status"]
        dep_status = result["source"]["dependencyAudit"]["status"]
        asset_statuses = [a["status"] for a in result["assets"]]
        if source_status == "detection" or "malware_detected" in asset_statuses:
            result["status"] = "dangerous"
        elif source_status in ("scan_error", "scanner_unavailable") or dep_status in ("scan_error", "scanner_unavailable") or not asset_statuses or any(
            s not in ("no_detection",) for s in asset_statuses
        ):
            result["status"] = "incomplete"
        elif dep_status == "vulnerabilities_found":
            result["status"] = "warning"
        else:
            result["status"] = "no_detection"
    except Exception as exc:
        result["status"] = "scan_error"
        result["notes"].append(str(exc)[:1000])
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", default="apps.json")
    parser.add_argument("--output", default="security-results.json")
    parser.add_argument("--max-asset-mb", type=int, default=500)
    parser.add_argument("--max-source-mb", type=int, default=300)
    args = parser.parse_args()

    catalog = json.loads(Path(args.catalog).read_text(encoding="utf-8"))
    apps = catalog.get("apps", [])
    report = {
        "schemaVersion": 1,
        "scanner": "Idol Security Scanner",
        "generatedAt": now_iso(),
        "policy": {
            "sourceScan": ["ClamAV", "OSV-Scanner"],
            "releaseAssetScan": ["ClamAV", "SHA-256"],
            "downloadsAreExecuted": False,
            "maxAssetMB": args.max_asset_mb,
            "maxSourceMB": args.max_source_mb,
            "meaning": "no_detection means no finding by the configured scanners; it is not a guarantee that a file is safe.",
        },
        "results": [],
    }
    for index, app in enumerate(apps, start=1):
        print(f"[{index}/{len(apps)}] Scanning {app.get('name', app.get('id', 'unknown'))}", flush=True)
        report["results"].append(scan_app(
            app,
            args.max_asset_mb * 1024 * 1024,
            args.max_source_mb * 1024 * 1024,
        ))
        time.sleep(1)

    Path(args.output).write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Report written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
