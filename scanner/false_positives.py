"""False-positive review registry.

Manual overrides recorded by a human reviewer, keyed by SHA-256 of the
affected file. Keys are sha256 prefixes or full hashes; values carry the
reviewer decision. A reviewed verdict never suppresses a ClamAV malware
detection automatically — it only adds a documented review annotation that
the report includes; download blocking for DANGEROUS stays enforced.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class FalsePositiveRegistry:
    def __init__(self, path: Path):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}
        self._entries: dict[str, dict[str, Any]] = {
            str(k).lower(): v for k, v in (data.get("reviews") or {}).items()
        }

    def lookup(self, sha256: str) -> dict[str, Any] | None:
        sha = (sha256 or "").lower()
        for prefix, review in self._entries.items():
            if sha.startswith(prefix) and len(prefix) >= 12:
                return dict(review, matched_prefix=prefix)
        return None
