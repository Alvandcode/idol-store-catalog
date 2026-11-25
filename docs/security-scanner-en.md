# Idol Security Scanner v2 — Technical Documentation

## Overview

An automated, fully open-source security scanner for the Idol Store catalog.
It reads `apps.json`, resolves each app's GitHub repository, downloads the
latest stable release's source archive and downloadable assets, and scans them
**without ever executing downloaded content**. Runs entirely on free GitHub
Actions infrastructure; no VirusTotal, no paid APIs, no dedicated server.

## Architecture

```
apps.json ──► Catalog Collector ──► Release Asset Downloader
                                        │
        ┌───────────────────────────────┤
        ▼                               ▼
 Source Code Scanner            Binary Malware Scanner
 (ClamAV, YARA, Semgrep,        (ClamAV, YARA, Binary Inspection:
  Gitleaks, OSV)                 format, signature, embedded execs,
                                 nested archives, hash verification)
        │                               │
        └──────────► Security Risk Engine ◄──── File Integrity Verifier
                            │
                     Report Generator ──► security-results.json (schema v2)
                            │
                  Idol Store Integration (Android app)
```

Modules live in `scanner/` with independent inputs/outputs/statuses;
`scripts/security_scan.py` is the workflow entry point.

## Report schema (v2)

Top level: `schemaVersion: 2`, `scannerVersion`, `generatedAt`, `policy`
(engine versions, limits, meaning of statuses), `summary`, `results[]`.

Each result contains (all required by the spec):

| Field | Meaning |
|---|---|
| `project_id`, `project_name`, `github_repository` | identity |
| `release_version`, `release_date` | scanned release |
| `scan_timestamp`, `scanner_version` | when/what scanned |
| `overall_status`, `risk_level` | SAFE / LOW_RISK / WARNING / DANGEROUS / INCOMPLETE / NOT_SCANNED / SCAN_ERROR + risk level |
| `status` | v1-compatible lowercase alias consumed by the Android app |
| `source_scan` | per-engine results with versions, timestamps, findings |
| `scanned_assets[]` | per-file result: `sha256`, `sha256_after_scan`, `integrity_verified`, per-engine findings, v1 `status` |
| `detections`, `vulnerabilities`, `warnings` | separate finding categories |
| `scan_errors`, `skipped_files` | explicit incompleteness |
| `execution_statistics` | API calls, bytes, cache hit |
| `from_cache` | result reused from the hash-keyed cache |

`scanned_assets[].status` uses v1 vocabulary (`no_detection`,
`malware_detected`, `suspicious_content`, `not_scanned_size_limit`,
`not_scanned_unsupported_format`, `download_or_scan_error`, `scan_error`).

## Risk engine rule order (first match wins)

1. **SCAN_ERROR** — technical failure recorded for the app.
2. **NOT_SCANNED** — no stable release.
3. **DANGEROUS** — ClamAV detection on sources or any asset, or a YARA rule with `severity = "critical"`.
4. **INCOMPLETE** — any required engine unavailable/errored; asset skipped (size limit, unsupported format, download error, corrupt archive).
5. **WARNING** — OSV vulnerabilities, medium/high YARA matches, semgrep findings, gitleaks secrets, suspicious binary structure (nested archives, embedded executables, unsigned APK is recorded as metadata).
6. **SAFE** — every required engine completed with no findings. This is *not* an absolute guarantee and the report says so explicitly.

Rules are unit-tested in `tests/test_risk_engine.py` and can be tuned in
`scanner/risk_engine.py`.

## Resource optimization

- **Hash-keyed cache** (`security-cache/`, committed by CI): results reused only when SHA-256 + policy key + scanner version all match; `SCAN_ERROR` results are never reused.
- **Bounded parallelism**: 3 apps, 2 assets concurrently (`config.py`).
- **Hard limits**: 700 MB asset, 300 MB source, 20k files, per-tool timeouts, GitHub API budget per app.
- **Zip bomb guards**: metadata-only expansion estimate (ratio > 200x or total > 2 GiB rejected before extraction); per-entry streaming caps; archive handling inside ClamAV with `--max-recursion=8`.
- **Signature DB caching**: `actions/cache` on `/var/lib/clamav`, `freshclam` only if older than 12 h.
- No file is ever sent to an external analysis service.

## Scanner hardening

- SSRF: HTTPS-only, host allowlist (github.com/api.github.com/codeload/objects.githubusercontent.com), redirects re-validated and capped.
- Path traversal & symlink entries rejected during extraction.
- Repository references validated against the `owner/repo` grammar — user-controlled strings never reach a shell (tools are invoked with argument lists, no shell).
- Downloads size-capped before disk write; hashes computed on the byte stream and re-verified after scanning.
- Reports cannot be manipulated by scanned projects: the scanner writes the only copy; a scanned repo has no write access to this repository.
- `GITHUB_TOKEN` is injected via env, used only in headers, never serialized into reports.
- Workflow `permissions: contents: write` only.

## Tool versions (pinned in the workflow)

ClamAV (distro), YARA (distro), Semgrep `>=1.78,<2`, OSV-Scanner `v2.0.3`,
Gitleaks `v8.28.0`, Python 3.12. Versions are also captured per run into
`policy.engines`.

## Tests

`python3 -m unittest discover -s tests -v`

- Risk engine rules (safe/dangerous/warning/incomplete/error paths)
- Safe extraction: traversal, absolute paths, symlinks, zip bomb ratio, corrupt archives
- URL validation / SSRF / repo-reference grammar
- Cache: hit, miss on hash change, never reuse SCAN_ERROR, corrupt files
- Binary inspection: signed/unsigned APK, embedded PE/ELF, nested archives, extensionless files, hash stability
- EICAR detection and clean-file negative test via ClamAV (CI)
- YARA rule matching via bundled rules (CI)
- Full pipeline integration with a fake GitHub client (no network)
- False-positive registry

No real malware is used anywhere; the only malware-like fixture is the EICAR
test string, which is industry-standard for antivirus verification.

## Known limitations

- No behavioral/sandbox analysis (not possible on free CI runners); static analysis only.
- CodeQL requires GitHub Advanced Security permissions not available to this free catalog setup; Semgrep + OSV-Scanner cover the source-analysis role.
- Files above the configured size limits are recorded as `INCOMPLETE`, never silently skipped.
- ClamAV detects only signatures it knows; the report never claims a file is malware-free.
