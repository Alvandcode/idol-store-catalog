"""End-to-end pipeline integration test with a fake GitHub client (no network).

Confirms the full flow: collector -> source extraction -> engines -> assets ->
risk engine -> cache. Engines are unavailable in test environments, so the
expected status is INCOMPLETE — never a clean result.
"""
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from scanner import models
from scanner.cache import ResultCache
from scanner.config import AppConfig
from scanner.false_positives import FalsePositiveRegistry
from scanner.pipeline import scan_app


class FakeClient:
    def __init__(self):
        self.calls = 0

    def api_json(self, path):
        self.calls += 1
        if "releases" not in path:
            return {"description": "fake"}
        return [{
            "tag_name": "v1.2.3", "draft": False, "prerelease": False,
            "published_at": "2026-01-01T00:00:00Z",
            "assets": [
                {"name": "app.apk", "size": 10, "browser_download_url": "https://github.com/a/b/releases/download/v1.2.3/app.apk"},
                {"name": "notes.txt", "size": 5, "browser_download_url": "https://github.com/a/b/releases/download/v1.2.3/notes.txt"},
            ],
        }]

    def download(self, url, max_bytes):
        self.calls += 1
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            if "/legacy.zip/refs/tags/" in url or "/zipball/" in url:
                z.writestr("repo-v1.2.3/main.py", "print('hello')\n")
            elif url.endswith("app.apk"):
                z.writestr("AndroidManifest.xml", b"\x03\x00")
            else:
                z.writestr("notes.txt", b"hi")
        return buf.getvalue()


APP = {"id": "test.app", "name": "TestApp", "github": "https://github.com/a/b"}


class PipelineIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cache = ResultCache(self.root / "cache")
        self.fp = FalsePositiveRegistry(self.root / "fp.json")
        self.config = AppConfig(max_asset_bytes=700 * 1024 * 1024, max_source_bytes=300 * 1024 * 1024)

    def _tools_missing(self):
        """Deterministically simulate unavailable scanner engines.

        CI installs all engines, so tests must not assume their absence —
        they force it instead (unit-test the policy, not the environment).
        """
        def unavailable(command, **kwargs):
            return {"available": False, "exit_code": None, "output": "not installed"}
        return (
            mock.patch("scanner.engines.clamav.run_tool", unavailable),
            mock.patch("scanner.engines.osv.run_tool", unavailable),
            mock.patch("scanner.engines.semgrep.run_tool", unavailable),
            mock.patch("scanner.engines.gitleaks.run_tool", unavailable),
            mock.patch("scanner.engines.yara._yara", None),
        )

    def test_full_flow_marks_incomplete_when_tools_missing(self):
        contexts = self._tools_missing()
        with contexts[0], contexts[1], contexts[2], contexts[3], contexts[4]:
            entry = scan_app(APP, FakeClient(), self.config, self.root, self.cache, self.fp)
        self.assertEqual(entry["overall_status"], models.INCOMPLETE)
        self.assertEqual(entry["status"], "incomplete")
        self.assertEqual(entry["release_version"], "v1.2.3")
        self.assertEqual(len(entry["source_scan"]["sha256_source_archive"]), 64)
        self.assertTrue(entry["scanned_assets"][0]["integrity_verified"])
        self.assertTrue(any(s["name"] == "notes.txt" for s in entry["skipped_files"]))
        self.assertTrue(entry["scan_errors"])

    def test_second_run_rejects_incomplete_cache(self):
        # First run here ends INCOMPLETE (forced engines unavailable);
        # incomplete results must never be frozen into the cache.
        contexts = self._tools_missing()
        with contexts[0], contexts[1], contexts[2], contexts[3], contexts[4]:
            scan_app(APP, FakeClient(), self.config, self.root, self.cache, self.fp)
            entry2 = scan_app(APP, FakeClient(), self.config, self.root, self.cache, self.fp)
        self.assertFalse(entry2["from_cache"])

    def test_complete_results_are_reused(self):
        first = scan_app(APP, FakeClient(), self.config, self.root, self.cache, self.fp)
        # Simulate a completed scan by promoting the stored entry to SAFE.
        key_dir = self.root / "cache" / "test_app"
        for path in key_dir.glob("*.json"):
            data = path.read_text(encoding="utf-8")
            data = data.replace('"overall_status": "INCOMPLETE"', '"overall_status": "SAFE"')
            data = data.replace('"status": "incomplete"', '"status": "no_detection"')
            path.write_text(data, encoding="utf-8")
        second = scan_app(APP, FakeClient(), self.config, self.root, self.cache, self.fp)
        self.assertTrue(second["from_cache"])
        self.assertEqual(second["overall_status"], "SAFE")  # reused the promoted entry

    def test_no_stable_release_is_not_scanned(self):
        class NoReleaseClient(FakeClient):
            def api_json(self, path):
                return [] if "releases" in path else {"description": "fake"}
        entry = scan_app(APP, NoReleaseClient(), self.config, self.root, self.cache, self.fp)
        self.assertEqual(entry["overall_status"], models.NOT_SCANNED)
        self.assertEqual(entry["status"], "not_scanned")

    def test_download_error_is_recorded_not_clean(self):
        class FailingAssetClient(FakeClient):
            def download(self, url, max_bytes):
                if url.endswith(".apk"):
                    from scanner.github_client import GitHubError
                    raise GitHubError("HTTP 500")
                return super().download(url, max_bytes)
        entry = scan_app(APP, FailingAssetClient(), self.config, self.root, self.cache, self.fp)
        asset = entry["scanned_assets"][0]
        self.assertEqual(asset["status"], "download_or_scan_error")
        self.assertIsNone(asset["sha256"])
        self.assertEqual(entry["overall_status"], models.INCOMPLETE)

    def test_size_limited_asset_is_not_scanned_not_safe(self):
        class HugeAssetClient(FakeClient):
            def api_json(self, path):
                data = super().api_json(path)
                if "releases" in path:
                    data[0]["assets"][0]["size"] = 2 * 1024 * 1024 * 1024
                return data
        entry = scan_app(APP, HugeAssetClient(), self.config, self.root, self.cache, self.fp)
        asset = entry["scanned_assets"][0]
        self.assertEqual(asset["status"], "not_scanned_size_limit")
        self.assertEqual(entry["overall_status"], models.INCOMPLETE)

    def test_report_payload_is_json_serializable_and_versioned(self):
        import json
        entry = scan_app(APP, FakeClient(), self.config, self.root, self.cache, self.fp)
        payload = json.dumps(entry, ensure_ascii=False)
        self.assertIn('"release_version": "v1.2.3"', payload)


if __name__ == "__main__":
    unittest.main()
