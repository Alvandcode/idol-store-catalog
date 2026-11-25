import unittest
from scanner.risk_engine import evaluate
from scanner import models


def ok_source(**overrides):
    source = {
        "clamav": {"status": "no_detection"},
        "dependency": {"status": "no_known_vulnerabilities", "vulnerabilities": []},
        "yara": {"status": "no_detection", "detections": []},
        "semgrep": {"status": "no_findings", "findings": []},
        "gitleaks": {"status": "no_findings", "findings": []},
    }
    source.update(overrides)
    return source


def ok_asset(name="app.apk", **overrides):
    asset = {
        "name": name,
        "status": "no_detection",
        "sha256": "a" * 64,
        "binary": {"status": "inspected", "flags": []},
        "clamav": {"status": "no_detection"},
        "yara": {"status": "no_detection", "detections": []},
    }
    asset.update(overrides)
    return asset


class RiskEngineTest(unittest.TestCase):
    def test_safe_requires_all_required_engines(self):
        status, risk, blocking, warnings = evaluate(
            source_scan=ok_source(), scanned_assets=[ok_asset()], had_release=True)
        self.assertEqual(status, models.SAFE)
        self.assertEqual(blocking, [])

    def test_nothing_found_is_not_safe_when_tool_missing(self):
        source = ok_source()
        source["clamav"]["status"] = "scanner_unavailable"
        status, *_ = evaluate(source_scan=source, scanned_assets=[ok_asset()], had_release=True)
        self.assertEqual(status, models.INCOMPLETE)

    def test_clamav_source_detection_is_dangerous(self):
        status, risk, blocking, _ = evaluate(
            source_scan=ok_source(clamav={"status": "detection", "detections": [{"signature": "X"}]}),
            scanned_assets=[], had_release=True)
        self.assertEqual(status, models.DANGEROUS)
        self.assertEqual(risk, "critical")

    def test_clamav_asset_detection_is_dangerous_and_blocking(self):
        asset = ok_asset(clamav={"status": "detection", "detections": [{"signature": "Win.Virus"}]})
        status, risk, blocking, _ = evaluate(source_scan=ok_source(), scanned_assets=[asset], had_release=True)
        self.assertEqual(status, models.DANGEROUS)
        self.assertTrue(blocking)

    def test_yara_critical_is_dangerous_medium_is_warning(self):
        asset = ok_asset(yara={"status": "detection", "detections": [{"rule": "r", "severity": "medium"}]})
        status, *_ = evaluate(source_scan=ok_source(), scanned_assets=[asset], had_release=True)
        self.assertEqual(status, models.WARNING)
        asset2 = ok_asset(yara={"status": "detection", "detections": [{"rule": "r", "severity": "critical"}]})
        status2, risk2, _, _ = evaluate(source_scan=ok_source(), scanned_assets=[asset2], had_release=True)
        self.assertEqual(status2, models.DANGEROUS)
        self.assertEqual(risk2, "critical")

    def test_osv_vulnerabilities_are_warning_not_dangerous(self):
        source = ok_source(dependency={"status": "vulnerabilities_found",
                                       "vulnerabilities": [{"id": "GHSA-x", "severity": "medium"}]})
        status, risk, _, warnings = evaluate(source_scan=source, scanned_assets=[ok_asset()], had_release=True)
        self.assertEqual(status, models.WARNING)
        self.assertEqual(risk, "medium")
        self.assertTrue(any("dependency" in w for w in warnings))

    def test_skipped_asset_makes_result_incomplete(self):
        asset = ok_asset(status="not_scanned_size_limit")
        status, *_ = evaluate(source_scan=ok_source(), scanned_assets=[asset], had_release=True)
        self.assertEqual(status, models.INCOMPLETE)

    def test_unsupported_format_asset_is_incomplete_not_safe(self):
        asset = ok_asset(status="not_scanned_unsupported_format")
        status, *_ = evaluate(source_scan=ok_source(), scanned_assets=[asset], had_release=True)
        self.assertEqual(status, models.INCOMPLETE)

    def test_no_release_is_not_scanned(self):
        status, *_ = evaluate(source_scan=ok_source(), scanned_assets=[], had_release=False)
        self.assertEqual(status, models.NOT_SCANNED)

    def test_technical_error_is_scan_error_not_clean(self):
        status, *_ = evaluate(source_scan=ok_source(), scanned_assets=[], had_release=True,
                              technical_error="disk full")
        self.assertEqual(status, models.SCAN_ERROR)

    def test_corrupt_archive_is_incomplete(self):
        asset = ok_asset(binary={"status": "corrupt_archive", "flags": []})
        status, *_ = evaluate(source_scan=ok_source(), scanned_assets=[asset], had_release=True)
        self.assertEqual(status, models.INCOMPLETE)

    def test_gitleaks_secrets_are_warning(self):
        source = ok_source(gitleaks={"status": "secrets_found", "findings": [{"rule": "r"}]})
        status, *_ = evaluate(source_scan=source, scanned_assets=[], had_release=True)
        self.assertEqual(status, models.WARNING)


if __name__ == "__main__":
    unittest.main()
