import json
import tempfile
import unittest
from pathlib import Path

from scanner.cache import ResultCache, cache_key
from scanner.util import sha256_bytes


class CacheTest(unittest.TestCase):
    def _cache(self, tmp):
        return ResultCache(Path(tmp))

    def test_store_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = self._cache(tmp)
            key = cache_key("sha-1", "sha-2")
            cache.store("app.id", key, {"release_version": "v1", "overall_status": "SAFE"})
            loaded = cache.load("app.id", key)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["release_version"], "v1")

    def test_different_hash_is_cache_miss(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = self._cache(tmp)
            cache.store("app.id", cache_key("aaa"), {"release_version": "v1"})
            self.assertIsNone(cache.load("app.id", cache_key("bbb")))

    def test_scan_error_never_reused(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = self._cache(tmp)
            key = cache_key("aaa")
            cache.store("app.id", key, {"release_version": "v1", "overall_status": "SCAN_ERROR"})
            self.assertIsNone(cache.load("app.id", key))

    def test_corrupt_cache_file_is_a_miss(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = self._cache(tmp)
            key = cache_key("aaa")
            path = cache._path("app.id", key)
            path.parent.mkdir(parents=True)
            path.write_text("{broken json", encoding="utf-8")
            self.assertIsNone(cache.load("app.id", key))

    def test_hash_changes_detect_new_content(self):
        h1 = sha256_bytes(b"content v1")
        h2 = sha256_bytes(b"content v2")
        self.assertNotEqual(h1, h2)


if __name__ == "__main__":
    unittest.main()
