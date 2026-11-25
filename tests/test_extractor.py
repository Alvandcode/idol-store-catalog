import os
import zipfile
import unittest
from pathlib import Path

from scanner.extractor import extract_zip_source, UnsafeArchive, find_source_root


def build_zip(entries, dest="out.zip"):
    buffer = io_bytes()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return buffer.getvalue()


def io_bytes():
    import io
    return io.BytesIO()


class ExtractorTest(unittest.TestCase):
    def test_normal_extraction(self):
        data = build_zip([("repo-1.0/main.py", b"print('hi')")])
        target = Path(self.enterContext(_tmpdir()))
        root = extract_zip_source(data, target)
        self.assertTrue((find_source_root(root) / "main.py").exists())

    def test_path_traversal_rejected(self):
        data = build_zip([("../../evil.txt", b"x")])
        with self.assertRaises(UnsafeArchive):
            extract_zip_source(data, Path(self.enterContext(_tmpdir())))

    def test_absolute_path_rejected(self):
        data = build_zip([("/etc/evil.txt", b"x")])
        with self.assertRaises(UnsafeArchive):
            extract_zip_source(data, Path(self.enterContext(_tmpdir())))

    def test_symlink_entry_rejected(self):
        info = zipfile.ZipInfo("link")
        import stat
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        buffer = io_bytes()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(info, "/etc/passwd")
        with self.assertRaises(UnsafeArchive):
            extract_zip_source(buffer.getvalue(), Path(self.enterContext(_tmpdir())))

    def test_zip_bomb_ratio_rejected(self):
        # High compression ratio: 50 MB of zeros compresses to ~50 KB.
        buffer = io_bytes()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("repo/zeros", b"\x00" * (50 * 1024 * 1024))
        with self.assertRaises(UnsafeArchive):
            extract_zip_source(buffer.getvalue(), Path(self.enterContext(_tmpdir())))

    def test_corrupt_zip_rejected(self):
        with self.assertRaises(UnsafeArchive):
            extract_zip_source(b"not a zip at all", Path(self.enterContext(_tmpdir())))


def _tmpdir():
    import tempfile
    from contextlib import contextmanager

    @contextmanager
    def ctx():
        with tempfile.TemporaryDirectory() as tmp:
            yield Path(tmp)
    return ctx()


if __name__ == "__main__":
    unittest.main()
