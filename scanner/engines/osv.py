"""OSV-Scanner engine: known vulnerabilities in dependency manifests."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..util import now_iso
from .base import base_result, run_tool, tool_version


def scan(path: Path) -> dict[str, Any]:
    result = base_result("osv-scanner")
    result["version"] = tool_version(["osv-scanner", "--version"], "osv-scanner")
    run = run_tool(["osv-scanner", "scan", "source", "-r", "--format", "json", str(path)], timeout=25 * 60)
    result.update({"available": run["available"], "exit_code": run["exit_code"], "scanned_at": now_iso()})
    output = run["output"] or ""
    if not run["available"]:
        result["status"] = "scanner_unavailable"
        return result
    parsed = None
    start = output.find("{")
    if start >= 0:
        try:
            parsed = json.loads(output[start:])
        except json.JSONDecodeError:
            parsed = None
    if parsed is None:
        if "No package sources found" in output and run["exit_code"] == 0:
            result["status"] = "no_manifests"
            return result
        result["status"] = "scan_error"
        result["error"] = output[-4000:]
        return result
    vulns = []
    for vuln_result in (parsed.get("results") or []):
        for vuln in (vuln_result.get("packages") or []):
            pkg = vuln.get("package", {})
            for v in (vuln.get("vulnerabilities") or []):
                vulns.append({
                    "tool": "osv-scanner",
                    "id": v.get("id", "?"),
                    "package": f"{pkg.get('ecosystem','?')}/{pkg.get('name','?')}",
                    "installed_version": pkg.get("version"),
                    "fixed_versions": [fix.get("fixed") for fix in (v.get("affected") or [{}])[0].get("ranges", []) if fix.get("fixed")][:5],
                    "summary": (v.get("summary") or v.get("details") or "")[:300],
                    "source": (vuln_result.get("source") or {}).get("path", "")[:200],
                    "severity": "high" if any(
                        s.get("type") == "CVSS_V3" and str(s.get("score", "")).startswith(("9", "10"))
                        for s in (v.get("severity") or [])
                    ) else "medium",
                })
    vulns = vulns[:300]
    result["vulnerabilities"] = vulns
    if run["exit_code"] == 1:
        result["status"] = "vulnerabilities_found"
    elif run["exit_code"] == 0:
        result["status"] = "no_known_vulnerabilities"
    else:
        result["status"] = "scan_error"
        result["error"] = output[-4000:]
    result.pop("output", None)
    return result
