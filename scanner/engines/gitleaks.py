"""Gitleaks engine: secret detection in source trees (no-git mode)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..util import now_iso
from .base import base_result, run_tool, tool_version


def scan(path: Path) -> dict[str, Any]:
    result = base_result("gitleaks")
    result["version"] = tool_version(["gitleaks", "version"], "gitleaks")
    report_path = path.parent / ("gitleaks-report-" + str(abs(hash(str(path)))) + ".json")
    run = run_tool([
        "gitleaks", "detect", "--source", str(path), "--no-git",
        "--report-format", "json", "--report-path", str(report_path),
        "--redact", "--no-banner",
        "--exit-code", "1",
    ], timeout=20 * 60)
    result.update({"available": run["available"], "exit_code": run["exit_code"], "scanned_at": now_iso()})
    if not run["available"]:
        result["status"] = "scanner_unavailable"
    elif run["exit_code"] in (0, 1) and report_path.exists():
        try:
            parsed = json.loads(report_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            parsed = []
        findings = [
            {
                "tool": "gitleaks",
                "rule": f.get("RuleID", "?"),
                "file": f.get("File", "")[:300],
                "line": f.get("StartLine"),
                "description": (f.get("Description") or "")[:200],
            }
            for f in (parsed or [])[:300]
        ]
        result["findings"] = findings
        result["status"] = "secrets_found" if findings else "no_findings"
        report_path.unlink(missing_ok=True)
    else:
        result["status"] = "scan_error"
        result["error"] = (run["output"] or "")[-4000:]
    result.pop("output", None)
    return result
