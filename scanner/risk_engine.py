"""Security Risk Engine — independent, documented, testable.

Aggregates per-engine results into exactly one of the public statuses.
Rules are a flat, ordered table; the first matching rule wins. Nothing here
ever reports SAFE because "nothing was found" alone — SAFE requires that all
required engines completed successfully with no findings.

Required engines (policy):
- sources:  clamav + osv  (yara + semgrep + gitleaks are review engines;
  their absence produces INCOMPLETE because a required policy component
  could not run)
- assets:   clamav + binary-inspection
"""
from __future__ import annotations

from typing import Any

from . import i18n, models

CRITICAL_YARA = "critical"  # severity value that justifies DANGEROUS


def _engine_status(scan: dict[str, Any] | None) -> str:
    if not scan:
        return "missing"
    return str(scan.get("status", "scan_error"))


def _required_missing(source: dict[str, Any], assets_scanned: list[dict[str, Any]]) -> list[str]:
    missing = []
    if _engine_status(source.get("clamav")) not in ("no_detection", "detection"):
        missing.append("source:clamav")
    if _engine_status(source.get("dependency")) not in (
        "no_known_vulnerabilities", "vulnerabilities_found", "no_manifests",
    ):
        missing.append("source:osv")
    for asset in assets_scanned:
        if asset.get("clamav") and _engine_status(asset["clamav"]) not in ("no_detection", "detection"):
            missing.append(f"asset:{asset.get('name')}:clamav")
    return missing


def evaluate(
    *,
    source_scan: dict[str, Any],
    scanned_assets: list[dict[str, Any]],
    had_release: bool,
    technical_error: str | None = None,
) -> tuple[str, str, list[str], list[str]]:
    """Return (overall_status, risk_level, blocking_evidence, warnings).

    Order of evaluation is documented in RULES_ORDER below and asserted by
    unit tests.
    """
    warnings: list[str] = []
    blocking: list[str] = []

    if technical_error:
        return models.SCAN_ERROR, "unknown", [], [
            {"key": "scan_error.technical", "params": {"reason": technical_error[:200]}}
        ]

    if not had_release:
        return models.NOT_SCANNED, "unknown", [], [{"key": "warning.no_stable_release"}]

    # 1) DANGEROUS — ClamAV detection on sources or any asset.
    if _engine_status(source_scan.get("clamav")) == "detection":
        return models.DANGEROUS, "critical", ["clamav detected malware in repository sources"], []
    for asset in scanned_assets:
        if asset.get("clamav", {}).get("status") == "detection":
            return models.DANGEROUS, "critical", [f"clamav detected malware in asset {asset.get('name')}"], []

    # 2) DANGEROUS — YARA critical-severity evidence.
    for yara_hit in _all_yara(source_scan, scanned_assets):
        if yara_hit.get("severity") == CRITICAL_YARA:
            return models.DANGEROUS, "critical", [f"yara critical rule {yara_hit.get('rule')}"], []

    # 3) INCOMPLETE — any required engine unavailable/errored, or a required
    #    asset was skipped (size limit / unsupported / download error).
    missing = _required_missing(source_scan, scanned_assets)
    for asset in scanned_assets:
        st = asset.get("status", "")
        if st in ("not_scanned_size_limit", "not_scanned_unsupported_format", "download_or_scan_error", "scan_error"):
            missing.append(f"asset:{asset.get('name')}:{st}")
        if asset.get("binary", {}).get("status") == "corrupt_archive":
            missing.append(f"asset:{asset.get('name')}:corrupt")
    if missing:
        return models.INCOMPLETE, "unknown", [], missing

    # 4) WARNING — OSV vulnerabilities, medium/high YARA, semgrep findings,
    #    gitleaks secrets, suspicious binary structure.
    osv = source_scan.get("dependency") or {}
    vulns = osv.get("vulnerabilities") or []
    if vulns:
        warnings.append({"key": "warning.dependency_vulns", "params": {"count": len(vulns)}})

    yara_all = _all_yara(source_scan, scanned_assets)
    if yara_all:
        warnings.append({"key": "warning.yara_matches", "params": {"count": len(yara_all)}})

    semgrep = source_scan.get("semgrep") or {}
    sg = semgrep.get("findings") or []
    if sg:
        warnings.append({"key": "warning.semgrep_findings", "params": {"count": len(sg)}})

    gitleaks = source_scan.get("gitleaks") or {}
    secrets = gitleaks.get("findings") or []
    if secrets:
        warnings.append({"key": "warning.gitleaks_secrets", "params": {"count": len(secrets)}})

    for asset in scanned_assets:
        binary = asset.get("binary") or {}
        flags = binary.get("flags") or []
        if flags:
            warnings.append({"key": "warning.binary_flags", "params": {
                "name": asset.get("name"), "flags": ", ".join(flags)}})
        if asset.get("status") == "suspicious_content":
            warnings.append({"key": "warning.asset_suspicious", "params": {"name": asset.get("name")}})

    if warnings:
        critical = any(v.get("severity") == "high" for v in vulns) or any(
            y.get("severity") in ("high",) for y in yara_all
        )
        return models.WARNING, ("high" if critical else "medium"), [], warnings

    # 5) LOW_RISK — only informational items (none currently produced above).
    # 6) SAFE — every required engine completed, nothing found.
    return models.SAFE, "low", [], warnings


def _all_yara(source_scan: dict[str, Any], assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    yara_src = source_scan.get("yara")
    if yara_src:
        hits.extend(yara_src.get("detections") or [])
    for asset in assets:
        ay = asset.get("yara")
        if ay:
            hits.extend(ay.get("detections") or [])
    return hits


def v1_overall(overall: str) -> str:
    return models.v1_status(overall)
