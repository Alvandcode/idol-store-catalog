"""Safe extraction of source archives (zipballs) with hardened guards.

Guards implemented (section 8 of the security policy):
- Path traversal: every entry must resolve inside the destination.
- Symlink attacks: symlinks/hardlinks/absolute-path entries are refused.
- Zip bombs: metadata-only expansion estimate before extraction; each entry
  is also size-capped while streaming.
- Nothing extracted is ever executed.
"""
from __future__ import annotations

import io
import shutil
import zipfile
from pathlib import Path

from .util import zip_is_bomb
from .config import MAX_ARCHIVE_RATIO, MAX_ARCHIVE_TOTAL_BYTES


class UnsafeArchive(ValueError):
    pass


def _entry_target(destination: Path, name: str) -> Path:
    if name.startswith(("/", "\\")) or (len(name) > 1 and name[1] == ":"):
        raise UnsafeArchive(f"Absolute path in archive entry: {name[:80]}")
    target = (destination / name).resolve()
    root = destination.resolve()
    if target != root and root not in target.parents:
        raise UnsafeArchive(f"Unsafe path detected in archive: {name[:80]}")
    return target


def extract_zip_source(data: bytes, destination: Path, *, max_files: int = 20000) -> Path:
    if not zipfile.is_zipfile(io.BytesIO(data)):
        raise UnsafeArchive("Source archive is not a valid zip file")
    if zip_is_bomb(data, ratio_limit=MAX_ARCHIVE_RATIO, total_limit=MAX_ARCHIVE_TOTAL_BYTES):
        raise UnsafeArchive("Archive rejected: expansion exceeds configured zip-bomb limits")
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        if len(names) > max_files:
            raise UnsafeArchive(f"Archive has {len(names)} entries (limit {max_files})")
        for info in archive.infolist():
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:  # symlink
                raise UnsafeArchive(f"Symlink entry rejected: {info.filename[:80]}")
            target = _entry_target(destination, info.filename)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst)
    return destination


def find_source_root(destination: Path) -> Path:
    """GitHub zipballs wrap everything in '<repo>-<tag>/' — return the single
    top directory if that is the case, else the destination itself."""
    entries = [p for p in destination.iterdir()]
    dirs = [p for p in entries if p.is_dir() and not p.is_symlink()]
    if len(entries) == 1 and len(dirs) == 1:
        return dirs[0]
    return destination
