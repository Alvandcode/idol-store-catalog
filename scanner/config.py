"""Runtime configuration and hard resource limits.

Every limit is explicit: the scanner never assumes unlimited free capacity.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

MAX_PARALLEL_APPS = 3          # bounded parallelism across projects
MAX_PARALLEL_ASSETS = 2        # bounded parallelism within one release
MAX_ARCHIVE_DEPTH = 3          # nested archives handled by ClamAV, not us
MAX_ARCHIVE_RATIO = 200        # suspicious expansion ratio (zip bomb guard)
MAX_ARCHIVE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB extracted cap
MAX_ASSET_BYTES = 700 * 1024 * 1024               # per release asset
MAX_SOURCE_BYTES = 300 * 1024 * 1024              # per source archive
DOWNLOAD_TIMEOUT_SECONDS = 120
TOOL_TIMEOUT_SECONDS = 45 * 60
MAX_REDIRECTS = 3
API_CALL_BUDGET_PER_APP = 60   # GitHub API calls per app per run
HTTP_RETRIES = 2
CACHE_POLICY_KEY = "idol-security-scanner-v2-policy-1"


@dataclass
class AppConfig:
    """Limits applied to a single application scan."""

    max_asset_bytes: int = MAX_ASSET_BYTES
    max_source_bytes: int = MAX_SOURCE_BYTES
    max_source_files: int = 20000
    skip_asset_globs: tuple = ()  # e.g. ("*.aab.sha256",) checked by fnmatch


@dataclass
class ScannerPaths:
    catalog: Path
    output: Path
    cache_dir: Path
    rules_dir: Path = field(default=Path(__file__).parent / "rules")
    false_positives: Path = field(default=Path(__file__).parent.parent / "scanner-config" / "false-positives.json")


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default
