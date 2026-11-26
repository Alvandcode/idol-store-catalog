"""Message-key translation layer.

Every status, asset status, warning and engine name has a stable message key.
The scan report references keys (stable across versions); the accompanying
i18n file maps each key to human text per locale. Adding a language means
adding one sibling entry per key in scanner/i18n/translations.json — no code
change, and unknown locales fall back to English.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_DEFAULT_FALLBACK = "en"

_TR_PATH = Path(__file__).parent / "i18n" / "translations.json"


def _load() -> dict[str, Any]:
    try:
        return json.loads(_TR_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {"keys": {}, "locales": [_DEFAULT_FALLBACK]}


_DATA = _load()
KEYS: dict[str, dict[str, str]] = _DATA.get("keys", {})
LOCALES: list[str] = _DATA.get("locales", [_DEFAULT_FALLBACK])


def available_locales() -> list[str]:
    return list(LOCALES)


def message(key: str, locale: str = "fa", **params: Any) -> str:
    entry = KEYS.get(key)
    if not entry:
        return key
    text = entry.get(locale) or entry.get(_DEFAULT_FALLBACK) or key
    if params:
        try:
            return text.format(**params)
        except (KeyError, IndexError):
            return text
    return text


def used_keys() -> list[str]:
    return sorted(KEYS)
