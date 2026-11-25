"""Shared tool-runner: version capture, timeouts, structured results.

Every engine returns a dict with: available, version, exit_code, output.
A missing or failing tool is never treated as a clean result.
"""
from __future__ import annotations

import subprocess
from typing import Any

from ..config import TOOL_TIMEOUT_SECONDS

_VERSION_CACHE: dict[str, str] = {}


def run_tool(command: list[str], *, cwd=None, timeout: int = TOOL_TIMEOUT_SECONDS) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        return {
            "available": True,
            "exit_code": proc.returncode,
            "output": proc.stdout or "",
        }
    except FileNotFoundError:
        return {"available": False, "exit_code": None, "output": "scanner executable not installed"}
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return {"available": True, "exit_code": 124, "output": out + "\nTIMED OUT"}


def tool_version(command: list[str], label: str) -> str | None:
    if label in _VERSION_CACHE:
        return _VERSION_CACHE[label]
    result = run_tool(command, timeout=60)
    version = None
    if result["available"] and result["exit_code"] == 0:
        first = (result["output"] or "").strip().splitlines()
        version = first[0].strip() if first else None
    _VERSION_CACHE[label] = version
    return version


def base_result(engine: str) -> dict[str, Any]:
    return {
        "engine": engine,
        "available": None,
        "version": None,
        "scanned_at": None,
        "exit_code": None,
        "status": "scan_error",
    }
