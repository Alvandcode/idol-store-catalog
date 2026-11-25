import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

HAVE_CLAMAV = shutil.which("clamscan") is not None
HAVE_YARA = shutil.which("yara") is not None

RULES = Path(__file__).resolve().parents[1] / "scanner" / "rules"


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


@unittest.skipUnless(HAVE_YARA, "yara not installed in this environment")
class YaraTest(unittest.TestCase):
    def test_b64_pe_rule_matches(self):
        import base64
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "encoded.txt"
            # base64 of 7-byte PE header prefix — must contain the rule's string.
            path.write_text(base64.b64encode(b"MZ\x90\x00\x03\x00\x00\x00").decode() + "\n")
            result = subprocess.run(
                ["yara", "-r", str(RULES / "yara" / "idol_custom.yar"), str(path)],
                capture_output=True, text=True, timeout=60)
            self.assertIn("idol_encoded_pe_header", result.stdout)

    def test_wrapper_parses_json(self):
        from scanner.engines import yara as yara_engine
        import base64
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "encoded.txt"
            path.write_text(base64.b64encode(b"MZ\x90\x00\x03\x00\x00\x00").decode())
            result = yara_engine.scan(path, RULES)
            self.assertEqual(result["status"], "detection")
            self.assertTrue(any(d["rule"] == "idol_encoded_pe_header" for d in result["detections"]))


if __name__ == "__main__":
    unittest.main()
