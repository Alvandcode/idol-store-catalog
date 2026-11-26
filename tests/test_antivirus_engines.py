"""YARA engine tests using yara-python bindings (same library the engine uses).

Runs everywhere yara-python is installed; in CI the workflow installs it.
No real malware: only the standard EICAR test string and synthetic fixtures.
"""
import base64
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

try:
    import yara as _yara
except ImportError:
    _yara = None

HAVE_YARAPY = _yara is not None
HAVE_CLAMAV = shutil.which("clamscan") is not None

RULES = Path(__file__).resolve().parents[1] / "scanner" / "rules"
EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")


@unittest.skipUnless(HAVE_CLAMAV, "clamscan not installed in this environment")
class ClamAVTest(unittest.TestCase):
    def test_eicar_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "eicar-test.txt"
            path.write_bytes(EICAR)
            result = subprocess.run(
                ["clamscan", "--infected", "--no-summary", str(path)],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 1, "EICAR test file must be detected")
            self.assertIn(" FOUND", result.stdout)

    def test_clean_file_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "clean.txt"
            path.write_bytes(b"ordinary harmless text\n" * 10)
            result = subprocess.run(
                ["clamscan", "--infected", "--no-summary", str(path)],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.strip(), "")

    def test_engine_wrapper_statuses(self):
        from scanner.engines import clamav
        with tempfile.TemporaryDirectory() as tmp:
            clean = Path(tmp) / "clean.txt"
            clean.write_bytes(b"clean\n")
            self.assertEqual(clamav.scan(clean)["status"], "no_detection")
            eicar = Path(tmp) / "eicar.txt"
            eicar.write_bytes(EICAR)
            self.assertEqual(clamav.scan(eicar)["status"], "detection")


@unittest.skipUnless(HAVE_YARAPY, "yara-python not installed in this environment")
class YaraRulesTest(unittest.TestCase):
    def _ruleset(self):
        return _yara.compile(filepaths={"idol_custom": str(RULES / "yara" / "idol_custom.yar")})

    def test_rules_compile(self):
        self._ruleset()

    def test_eicar_rule_matches(self):
        matches = [m.rule for m in self._ruleset().match(data=EICAR)]
        self.assertIn("idol_eicar_test_file", matches)

    def test_b64_pe_rule_matches(self):
        fixture = base64.b64encode(b"MZ\x90\x00\x03\x00\x00\x00").decode().encode()
        matches = [m.rule for m in self._ruleset().match(data=fixture)]
        self.assertIn("idol_encoded_pe_header", matches)

    def test_clean_text_matches_nothing(self):
        matches = self._ruleset().match(data=b"ordinary harmless text\n" * 10)
        self.assertEqual(matches, [])


@unittest.skipUnless(HAVE_YARAPY, "yara-python not installed in this environment")
class YaraEngineWrapperTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_wrapper_detects_encoded_pe(self):
        from scanner.engines import yara as yara_engine
        target = self.root / "encoded.txt"
        target.write_text(base64.b64encode(b"MZ\x90\x00\x03\x00\x00\x00").decode())
        result = yara_engine.scan(target, RULES)
        self.assertEqual(result["status"], "detection")
        self.assertTrue(any(d["rule"] == "idol_encoded_pe_header" for d in result["detections"]))

    def test_wrapper_no_detection(self):
        from scanner.engines import yara as yara_engine
        target = self.root / "clean.txt"
        target.write_text("plain safe text\n")
        result = yara_engine.scan(target, RULES)
        self.assertEqual(result["status"], "no_detection")
        self.assertEqual(result["detections"], [])

    def test_wrapper_unavailable_without_rules(self):
        from scanner.engines import yara as yara_engine
        target = self.root / "clean.txt"
        target.write_text("plain\n")
        result = yara_engine.scan(target, self.root / "no-rules-here")
        self.assertEqual(result["status"], "scanner_unavailable")


if __name__ == "__main__":
    unittest.main()
