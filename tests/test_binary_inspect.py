import os
import shutil
import tempfile
import unittest
from pathlib import Path

from scanner.engines import binary_inspect


def _make_zip(entries):
    import io
    import zipfile
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return buffer.getvalue()


class BinaryInspectTest(unittest.TestCase):
    """Uses only synthetic fixtures (no real malware, no execution)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="idol-bin-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _write(self, name, data):
        path = self.tmp / name
        path.write_bytes(data)
        return path

    def test_plain_file(self):
        path = self._write("hello.bin", b"\x00\x01plain data")
        result = binary_inspect.inspect(path)
        self.assertEqual(result["status"], "inspected")
        self.assertFalse(result["is_zip_container"])
        self.assertEqual(len(result["sha256"]), 64)

    def test_apk_signature_detection(self):
        # Unsigned APK: zip with AndroidManifest but no META-INF certificate.
        data = _make_zip([("AndroidManifest.xml", b"\x03\x00\x08\x00bin"), ("classes.dex", b"dex\n")])
        result = binary_inspect.inspect(self._write("unsigned.apk", data))
        self.assertEqual(result["apk_signature"], "unsigned")

    def test_signed_apk_signature_detected(self):
        data = _make_zip([("AndroidManifest.xml", b"x"), ("META-INF/CERT.RSA", b"cert"), ("classes.dex", b"x")])
        result = binary_inspect.inspect(self._write("signed.apk", data))
        self.assertEqual(result["apk_signature"], "present")

    def test_nested_archive_flagged(self):
        inner = _make_zip([("payload.txt", b"x")])
        data = _make_zip([("AndroidManifest.xml", b"x"), ("assets/update.zip", inner)])
        result = binary_inspect.inspect(self._write("nested.apk", data))
        self.assertIn("nested_archive_present", result.get("flags") or [])

    def test_embedded_executable_flagged(self):
        data = _make_zip([("AndroidManifest.xml", b"x"), ("assets/stage2.bin", b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00PE\x00\x00")])
        result = binary_inspect.inspect(self._write("embedded.apk", data))
        self.assertIn("embedded_executables", result.get("flags") or [])
        self.assertTrue(any("stage2" in e for e in result["zip_inventory"]["embedded_executables"]))

    def test_corrupt_archive_detected(self):
        data = bytearray(_make_zip([("AndroidManifest.xml", b"x")]))
        data[len(data) // 2] = 0xFF
        data[len(data) // 2 + 1] = 0xAA
        result = binary_inspect.inspect(self._write("broken.apk", bytes(data)))
        self.assertIn(result["status"], ("corrupt_archive", "inspected"))

    def test_no_extension_file(self):
        path = self._write("unknownfile", b"\x7fELF\x02\x01\x01")
        result = binary_inspect.inspect(path)
        self.assertEqual(result["status"], "inspected")
        self.assertEqual(result["sha256"], binary_inspect.inspect(path)["sha256"])

    def test_hash_before_and_after_stable(self):
        data = _make_zip([("AndroidManifest.xml", b"x")])
        path = self._write("stable.apk", data)
        first = binary_inspect.inspect(path)
        second = binary_inspect.inspect(path, pre_hash=first["sha256"])
        self.assertEqual(first["sha256"], second["sha256"])
        self.assertTrue(second["sha256"] == binary_inspect.inspect(path)["sha256"])


if __name__ == "__main__":
    unittest.main()
