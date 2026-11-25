"""YARA engine with the project's custom low-false-positive rule set.

Rule severities are explicit in the .yar files; a rule only escalates the
overall status when it declares severity "critical" (documented in
risk_engine.py). Everything else is a review item.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..util import now_iso
from .base import base_result, run_tool, tool_version

SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "informational"}


def _load_rules(rules_dir: Path) -> list[str]:
    return sorted(str(p) for p in rules_dir.glob("*.yar"))


def _parse_findings(output: str) -> list[dict[str, str]]:
    """Parse `yara --json` output (JSON Lines: one object per match)."""
    findings = []
    for line in (output or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            match = json.loads(line)
        except json.JSONDecodeError:
            continue
        meta = match.get("meta", {}) or {}
        first_path = ""
        strings = match.get("strings") or []
        if strings and isinstance(strings[0], dict):
            first_path = strings[0].get("path", "") or strings[0].get("filename", "")
        findings.append({
            "tool": "yara",
            "rule": match.get("rule", "?"),
            "severity": SEVERITY_MAP.get(str(meta.get("severity", "medium")).lower(), "medium"),
            "file": str(first_path)[:300],
            "description": str(meta.get("description", ""))[:300],
        })
    return findings[:200]


def scan(path: Path, rules_dir: Path) -> dict[str, Any]:
    result = base_result("yara")
    rule_files = _load_rules(rules_dir)
    if not rule_files:
        result["status"] = "scanner_unavailable"
        result["error"] = "no YARA rule files found"
        return result
    result["version"] = tool_version(["yara", "--version"], "yara")
    # yara --json requires -s? use 'yara -a 600 -f -p 8 --json -r rules target'
    run = run_tool(
        ["yara", "--json", "-a", "600", "-r", *rule_files, str(path)],
        timeout=20 * 60,
    )
    result.update({"available": run["available"], "exit_code": run["exit_code"], "scanned_at": now_iso()})
    if not run["available"]:
        result["status"] = "scanner_unavailable"
    elif run["exit_code"] == 0:
        result["detections"] = _parse_findings(run["output"])
        result["status"] = "detection" if result["detections"] else "no_detection"
    else:
        result["status"] = "scan_error"
        result["error"] = (run["output"] or "")[-4000:]
    result.pop("output", None)
    return result
