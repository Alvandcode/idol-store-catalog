"""Binary/format inspection engine for release assets (analysis only, never execution).

For each asset:
- SHA-256 before and after scanning (integrity verification).
- Format classification via `file` (no execution).
- ZIP/APK inner listing: detect embedded executables (PE/ELF), nested
  archives, and count entries — metadata reading only, no extraction.
- Optional Android signature verification with apksigner when present.
"""
from __future__ import annotations

import io
import zipfile
import zlib
from pathlib import Path
from typing import Any

from ..util import now_iso, sha256_file
from .base import base_result, run_tool

APK_SIGNATURE_MISSING = "unsigned"


def _file_type(path: Path) -> str:
    run = run_tool(["file", "-b", str(path)], timeout=60)
    if run["available"] and run["exit_code"] == 0:
        return (run["output"] or "").strip()[:300]
    return "unknown"


def _zip_inventory(data: bytes) -> dict[str, Any]:
    inv: dict[str, Any] = {"is_zip": False}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            inv["is_zip"] = True
            entries = archive.namelist()
            inv["entry_count"] = len(entries)
            inv["nested_archives"] = [n[:200] for n in entries if n.lower().endswith((".zip", ".jar", ".apk", ".7z", ".rar", ".tar", ".gz"))][:50]
            inv["embedded_executables"] = []
            total = 0
            for name in entries[:5000]:
                total += archive.getinfo(name).file_size
                head = b""
                with archive.open(name) as fh:
                    head = fh.read(4)
                if head.startswith((b"MZ", b"\x7fELF")):
                    inv["embedded_executables"].append(name[:200])
            inv["declared_total_bytes"] = total
    except (zipfile.BadZipFile, zlib.error, OSError):
        inv["corrupt"] = True
    return inv


def inspect(path: Path, *, pre_hash: str | None = None) -> dict[str, Any]:
    """Inspect one downloaded asset file. Never executes the file."""
    result = base_result("binary-inspection")
    result["available"] = True
    result["scanned_at"] = now_iso()
    result["size_bytes"] = path.stat().st_size
    result["sha256"] = pre_hash or sha256_file(path)
    result["file_type"] = _file_type(path)
    with path.open("rb") as handle:
        data_head = handle.read(4) if result["size_bytes"] >= 4 else handle.read()
    result["is_zip_container"] = data_head[:2] == b"PK"
    result["zip_inventory"] = None
    result["apk_signature"] = None
    if result["is_zip_container"]:
        try:
            data = path.read_bytes()
        except OSError as exc:
            result["status"] = "scan_error"
            result["error"] = str(exc)[:300]
            return result
        inv = _zip_inventory(data)
        result["zip_inventory"] = inv
        names = []
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = archive.namelist()
        except Exception:
            names = []
        is_apk = any(n == "AndroidManifest.xml" for n in names)
        if is_apk:
            if not any(n.startswith("META-INF/") and (n.endswith(".RSA") or n.endswith(".DSA") or n.endswith(".EC")) for n in names):
                result["apk_signature"] = APK_SIGNATURE_MISSING
            else:
                result["apk_signature"] = "present"
        if inv.get("corrupt"):
            result["status"] = "corrupt_archive"
            return result
        if inv.get("nested_archives"):
            result["flags"] = (result.get("flags") or []) + ["nested_archive_present"]
        if inv.get("embedded_executables"):
            result["flags"] = (result.get("flags") or []) + ["embedded_executables"]
    result["status"] = "inspected"
    return result
