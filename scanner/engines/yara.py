"""YARA engine using yara-python bindings (deterministic across environments).

The apt `yara` CLI varies between runner distributions; the Python bindings
are pinned via pip and behave identically locally and in CI.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..util import now_iso
from .base import base_result

try:
    import yara as _yara  # yara-python
except ImportError:  # pragma: no cover - CI installs yara-python
    _yara = None

MAX_SCAN_FILE_BYTES = 100 * 1024 * 1024
MAX_FILES = 30000
SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "informational"}

_RULES_CACHE: dict[str, Any] = {}


def _load_ruleset(rules_dir: Path) -> Any | None:
    key = str(rules_dir.resolve())
    if key in _RULES_CACHE:
        return _RULES_CACHE[key]
    if _yara is None:
        return None
    rule_files = {p.stem: str(p) for p in sorted(rules_dir.glob("**/*.yar"))}
    if not rule_files:
        return None
    try:
        ruleset = _yara.compile(filepaths=rule_files)
    except _yara.Error as exc:
        raise RuntimeError(f"YARA rule compilation failed: {exc}") from exc
    _RULES_CACHE[key] = ruleset
    return ruleset


def _iter_files(root: Path):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            path = Path(dirpath) / name
            try:
                if path.is_symlink() or path.stat().st_size > MAX_SCAN_FILE_BYTES:
                    continue
            except OSError:
                continue
            count += 1
            if count > MAX_FILES:
                return
            yield path


def _match_file(ruleset: Any, path: Path) -> list[dict[str, str]]:
    findings = []
    try:
        matches = ruleset.match(str(path), timeout=120)
    except _yara.TimeoutError:
        return [{"tool": "yara", "rule": "SCAN_TIMEOUT", "severity": "informational", "file": str(path)[:300], "description": "rule evaluation timed out"}]
    except (_yara.Error, OSError):
        return []
    for match in matches:
        meta = match.meta or {}
        findings.append({
            "tool": "yara",
            "rule": match.rule,
            "severity": SEVERITY_MAP.get(str(meta.get("severity", "medium")).lower(), "medium"),
            "file": str(path)[:300],
            "description": str(meta.get("description", ""))[:300],
        })
    return findings


def scan(path: Path, rules_dir: Path) -> dict[str, Any]:
    result = base_result("yara")
    if _yara is None:
        result["status"] = "scanner_unavailable"
        result["error"] = "yara-python not installed"
        return result
    result["version"] = _yara.__version__
    try:
        ruleset = _load_ruleset(rules_dir)
    except RuntimeError as exc:
        result["status"] = "scan_error"
        result["error"] = str(exc)[:500]
        return result
    if ruleset is None:
        result["status"] = "scanner_unavailable"
        result["error"] = "no YARA rule files found"
        return result
    result["available"] = True
    result["scanned_at"] = now_iso()
    detections: list[dict[str, str]] = []
    for file_path in _iter_files(path if path.is_dir() else path.parent):
        detections.extend(_match_file(ruleset, file_path))
    result["detections"] = detections[:200]
    result["status"] = "detection" if detections else "no_detection"
    return result
