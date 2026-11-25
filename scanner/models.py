"""Status vocabulary. v2 statuses are uppercase; v1-compatible lowercase
aliases keep the existing Android app working without changes.
"""
from __future__ import annotations

# App-level (report.results[].overall_status)
APP_STATUSES = (
    "SAFE",          # all required scans completed, nothing found
    "LOW_RISK",      # minor findings only (e.g. informational gitleaks hits)
    "WARNING",       # vulnerabilities or suspicious behaviour needing review
    "DANGEROUS",     # malware identified with credible evidence
    "INCOMPLETE",    # part of the scans did not run or tool unavailable
    "NOT_SCANNED",   # no scan performed yet
    "SCAN_ERROR",    # scan failed with a technical error
)

# v1 aliases consumed by the Idol Store Android app
V1_ALIASES = {
    "SAFE": "no_detection",
    "LOW_RISK": "no_detection",
    "WARNING": "warning",
    "DANGEROUS": "dangerous",
    "INCOMPLETE": "incomplete",
    "NOT_SCANNED": "not_scanned",
    "SCAN_ERROR": "scan_error",
}

ASSET_STATUSES = (
    "no_detection",          # scanners ran, nothing found (not a guarantee)
    "malware_detected",      # credible malware evidence -> blocks download
    "suspicious_content",    # needs human review -> WARNING
    "not_scanned_size_limit",
    "not_scanned_unsupported_format",
    "download_or_scan_error",
    "scan_error",
)

SAFE = "SAFE"
LOW_RISK = "LOW_RISK"
WARNING = "WARNING"
DANGEROUS = "DANGEROUS"
INCOMPLETE = "INCOMPLETE"
NOT_SCANNED = "NOT_SCANNED"
SCAN_ERROR = "SCAN_ERROR"

# Which app statuses block a download in the store UI: only DANGEROUS.
BLOCKING_STATUSES = ("DANGEROUS",)

ENGINE_CLAMAV = "clamav"
ENGINE_YARA = "yara"
ENGINE_SEMGREP = "semgrep"
ENGINE_GITLEAKS = "gitleaks"
ENGINE_OSV = "osv-scanner"
ENGINE_BINARY = "binary-inspection"


def v1_status(overall: str) -> str:
    return V1_ALIASES.get(overall, "scan_error")
