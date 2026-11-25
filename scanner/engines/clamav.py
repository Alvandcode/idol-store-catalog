"""ClamAV engine (required engine for both sources and release assets).

Archive limits are delegated to clamscan itself (max-files, max-recursion,
max-scansize) so nested archives and bombs are handled inside the engine.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..util import now_iso
from .base import base_result, run_tool, tool_version

SCAN_LIMITS = [
    "--max-scansize=900M", "--max-filesize=250M", "--max-files=10000",
    "--max-recursion=8", "--max-dir-recursion=12", "--alert-encrypted=yes",
    "--infected", "--no-summary",
]


def _detections(output: str) -> list[dict[str, str]]:
    findings = []
    for line in (output or "").splitlines():
        if line.strip().endswith(" FOUND"):
            findings.append({"tool": "clamav", "signature": line.split(" FOUND")[0].split(": ", 1)[-1].strip(), "raw": line.strip()[:300]})
    return findings[:200]


def scan(path: Path) -> dict[str, Any]:
    result = base_result("clamav")
    result["version"] = tool_version(["clamscan", "--version"], "clamav")
    run = run_tool(["clamscan", "--recursive", *SCAN_LIMITS, str(path)])
    result.update({"available": run["available"], "exit_code": run["exit_code"], "scanned_at": now_iso()})
    output = run["output"] or ""
    result["detections"] = _detections(output)
    if not run["available"]:
        result["status"] = "scanner_unavailable"
    elif run["exit_code"] == 0:
        result["status"] = "no_detection"
        result["detections"] = []
    elif run["exit_code"] == 1:
        result["status"] = "detection"
    elif run["exit_code"] == 2:
        result["status"] = "scan_error"
        result["error"] = output[-4000:]
    result.pop("output", None)
    return result
