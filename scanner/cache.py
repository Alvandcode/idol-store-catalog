"""Hash-keyed result cache.

Key: SHA-256 of the exact scanned content + policy key + engine versions.
A cached entry is only reused when:
- the hash matches the content that was actually downloaded (re-verified),
- the scanner policy and engine versions are identical,
- the previous result did not end in SCAN_ERROR (errors are always re-scanned).
The cache is a plain JSON file tree, committed by the workflow, so repeated
runs never re-download or re-scan unchanged files.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from . import SCANNER_VERSION
from .config import CACHE_POLICY_KEY
from .util import atomic_write_json


def cache_key(*hashes: str) -> str:
    digest = hashlib.sha256()
    digest.update(CACHE_POLICY_KEY.encode())
    for value in sorted(hashes):
        digest.update(value.encode())
    return digest.hexdigest()


class ResultCache:
    def __init__(self, root: Path):
        self.root = root

    def _path(self, app_id: str, key: str) -> Path:
        return self.root / app_id.replace(".", "_").replace("/", "_")[:80] / (key[:32] + ".json")

    def load(self, app_id: str, key: str) -> dict[str, Any] | None:
        path = self._path(app_id, key)
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return None
        if entry.get("scanner_version") != SCANNER_VERSION:
            return None
        if entry.get("policy_key") != CACHE_POLICY_KEY:
            return None
        if entry.get("status") == "SCAN_ERROR" or entry.get("overall_status") == "SCAN_ERROR":
            return None
        return entry

    def store(self, app_id: str, key: str, payload: dict[str, Any]) -> None:
        entry = dict(payload)
        entry["cache_key"] = key
        entry["scanner_version"] = SCANNER_VERSION
        entry["policy_key"] = CACHE_POLICY_KEY
        atomic_write_json(self._path(app_id, key), entry)
