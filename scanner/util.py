"""Small shared helpers: hashing, timestamps, safe filenames, atomic writes."""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_filename(name: str) -> str:
    """Filesystem-safe identifier used for cache paths. Never a shell argument."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:120]


def atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def is_zip(data: bytes) -> bool:
    return len(data) >= 4 and data[:2] == b"PK"


def zip_is_bomb(data: bytes, *, ratio_limit: int, total_limit: int) -> bool:
    """Estimate archive expansion without extracting anything.

    Purely reads central directory metadata and inflates each entry into a
    counter (never writing files), so it is safe against path traversal and
    symlink tricks.
    """
    if not is_zip(data):
        return False
    try:
        with zipfile.ZipFile(__import__("io").BytesIO(data)) as archive:
            total = 0
            for info in archive.infolist():
                total += info.file_size
                if info.compress_size and info.file_size / info.compress_size > ratio_limit:
                    return True
            return total > total_limit
    except (zipfile.BadZipFile, zlib.error):
        return False


def iterate_hex_chunks(value: str) -> Iterator[str]:
    yield value
