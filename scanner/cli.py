"""CLI entry point: orchestrate the full catalog scan and write the report."""
from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import REPORT_SCHEMA_VERSION, SCANNER_NAME, SCANNER_VERSION
from . import i18n as i18n_mod
from .cache import ResultCache
from .config import AppConfig, ScannerPaths, MAX_PARALLEL_APPS
from .engines import base
from .false_positives import FalsePositiveRegistry
from .github_client import GitHubClient, RateLimitError
from .models import APP_STATUSES
from .pipeline import scan_app
from .risk_engine import v1_overall
from .util import atomic_write_json


def build_report_payload(results: list[dict], policy: dict) -> dict:
    return {
        "schemaVersion": REPORT_SCHEMA_VERSION,
        "scanner": SCANNER_NAME,
        "scannerVersion": SCANNER_VERSION,
        "generatedAt": policy.pop("_generated_at"),
        "policy": policy,
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="idol-security-scanner")
    parser.add_argument("--catalog", default="apps.json")
    parser.add_argument("--output", default="security-results.json")
    parser.add_argument("--cache-dir", default="security-cache")
    parser.add_argument("--max-asset-mb", type=int, default=700)
    parser.add_argument("--max-source-mb", type=int, default=300)
    args = parser.parse_args(argv)

    catalog_path = Path(args.catalog)
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    apps = catalog.get("apps", [])

    paths = ScannerPaths(catalog=catalog_path, output=Path(args.output), cache_dir=Path(args.cache_dir))
    config = AppConfig(
        max_asset_bytes=args.max_asset_mb * 1024 * 1024,
        max_source_bytes=args.max_source_mb * 1024 * 1024,
    )
    client = GitHubClient(token=None)  # token is injected via env by the workflow, never stored
    cache = ResultCache(paths.cache_dir)
    fp_registry = FalsePositiveRegistry(paths.false_positives)
    community_rules_dir = paths.cache_dir / "yara-community"

    # Version audit: which engines are actually available before scanning?
    try:
        import yara as _yara_mod
        yara_version = _yara_mod.__version__
    except ImportError:
        yara_version = None
    engine_versions = {
        "clamav": base.tool_version(["clamscan", "--version"], "clamav"),
        "yara": yara_version,
        "semgrep": base.tool_version(["semgrep", "--version"], "semgrep"),
        "gitleaks": base.tool_version(["gitleaks", "version"], "gitleaks"),
        "osv-scanner": base.tool_version(["osv-scanner", "--version"], "osv-scanner"),
    }

    policy = {
        "_generated_at": __import__("scanner.util", fromlist=["now_iso"]).now_iso(),
        "engines": {k: v for k, v in engine_versions.items()},
        "required_engines": ["clamav", "osv-scanner"],
        "review_engines": ["yara", "semgrep", "gitleaks"],
        "downloadsAreExecuted": False,
        "maxAssetMB": args.max_asset_mb,
        "maxSourceMB": args.max_source_mb,
        "parallelApps": MAX_PARALLEL_APPS,
        "meaning": (
            "no_detection/SAFE means the configured scanners completed and found nothing; "
            "it is not an absolute guarantee of safety. Files are never executed."
        ),
        "statuses": list(APP_STATUSES),
    }

    results: list[dict] = []
    rate_limit_hits = 0
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_APPS) as pool:
        futures = [
            pool.submit(
                scan_app, app,
                GitHubClient(token=__import__("os").environ.get("GITHUB_TOKEN")),
                config, paths.rules_dir, cache, fp_registry, community_rules_dir,
            )
            for app in apps
        ]
        for app, future in zip(apps, futures):
            try:
                results.append(future.result())
                print(f"[done] {app.get('name', app.get('id'))}", flush=True)
            except RateLimitError as exc:
                rate_limit_hits += 1
                print(f"[rate-limit] {app.get('name')}: {exc}", flush=True)
                results.append({
                    "id": str(app.get("id") or app.get("name") or "unknown"),
                    "name": app.get("name"),
                    "github_repository": app.get("github"),
                    "overall_status": "NOT_SCANNED",
                    "status": v1_overall("NOT_SCANNED"),
                    "scan_timestamp": policy["_generated_at"],
                    "warnings": [f"GitHub rate limit reached; not scanned this run: {exc}"],
                })
            except Exception as exc:  # keep the run alive
                results.append({
                    "id": str(app.get("id") or app.get("name") or "unknown"),
                    "name": app.get("name"),
                    "overall_status": "SCAN_ERROR",
                    "status": v1_overall("SCAN_ERROR"),
                    "scan_timestamp": policy["_generated_at"],
                    "scan_errors": [str(exc)[:500]],
                })

    payload = build_report_payload(results, policy)
    payload["summary"] = {
        "total": len(results),
        "by_status": {
            s: sum(1 for r in results if r.get("overall_status") == s) for s in APP_STATUSES
        },
        "cache_hits": sum(1 for r in results if r.get("from_cache")),
        "rate_limit_hits": rate_limit_hits,
    }
    policy["communityRules"] = {
        "enabled": community_rules_dir.is_dir() and any(community_rules_dir.glob("*.yar")),
        "directory": "security-cache/yara-community",
        "manifest": "security-cache/yara-sources.json",
        "note": "community rules are severity-capped at medium (review only)",
    }
    policy["i18n"] = {"locales": i18n_mod.available_locales(), "file": paths.output.name.replace(".json", "-i18n.json")}
    atomic_write_json(paths.output, payload)

    # Publish the full translation catalog next to the report so any UI can
    # render statuses/warnings in any supported locale.
    i18n_payload = {
        "schemaVersion": 1,
        "locales": i18n_mod.available_locales(),
        "fallbackLocale": "en",
        "keys": i18n_mod.KEYS,
        "meaning": i18n_mod.message("meaning.not_absolute", "en"),
    }
    atomic_write_json(paths.output.parent / (paths.output.name.replace(".json", "-i18n.json")), i18n_payload)
    print(f"Report written to {paths.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
