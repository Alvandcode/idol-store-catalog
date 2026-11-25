"""Semgrep static analysis engine using the project's bundled offline rules.

Using local rules (scanner/rules/semgrep/) keeps runs deterministic, fast and
free; no registry download per run. Rules are tuned to avoid generic false
positives; findings are review items (WARNING), not malware verdicts.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..util import now_iso
from .base import base_result, run_tool, tool_version


def scan(path: Path, rules_dir: Path) -> dict[str, Any]:
    result = base_result("semgrep")
    rules_file = rules_dir / "semgrep" / "idol-security.yaml"
    if not rules_file.exists():
        result["status"] = "scanner_unavailable"
        result["error"] = "bundled semgrep rules missing"
        return result
    result["version"] = tool_version(["semgrep", "--version"], "semgrep")
    report_path = path.parent / ("semgrep-report-" + str(abs(hash(str(path)))) + ".json")
    run = run_tool([
        "semgrep", "scan",
        "--config", str(rules_file),
        "--json", "--quiet",
        "--metrics=off",
        "--max-target-bytes", "3000000",
        "--timeout", "30",
        "--timeout-threshold", "3",
        "--jobs", "2",
        "-o", str(report_path),
        str(path),
    ], timeout=30 * 60)
    result.update({"available": run["available"], "exit_code": run["exit_code"], "scanned_at": now_iso()})
    if not run["available"]:
        result["status"] = "scanner_unavailable"
    elif run["exit_code"] in (0, 1) and report_path.exists():
        try:
            parsed = json.loads(report_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            parsed = {}
        findings = [
            {
                "tool": "semgrep",
                "rule": f.get("check_id", "?").split(".")[-1],
                "file": f.get("path", "")[:300],
                "line": (f.get("start") or {}).get("line"),
                "message": (f.get("extra") or {}).get("message", "")[:300],
                "severity": (f.get("extra") or {}).get("severity", "INFO").lower(),
            }
            for f in (parsed.get("results") or [])[:300]
        ]
        result["findings"] = findings
        result["status"] = "findings" if findings else "no_findings"
        if parsed.get("errors"):
            result["engine_errors"] = str(parsed["errors"])[:2000]
            if not findings and run["exit_code"] not in (0, 1):
                result["status"] = "scan_error"
        report_path.unlink(missing_ok=True)
    else:
        result["status"] = "scan_error"
        result["error"] = (run["output"] or "")[-4000:]
    result.pop("output", None)
    return result
