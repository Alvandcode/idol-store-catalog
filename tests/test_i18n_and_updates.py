import json
import tempfile
import unittest
import zipfile
import io
from pathlib import Path

from scanner import i18n, models


class I18nTest(unittest.TestCase):
    def test_every_status_has_fa_and_en(self):
        for status in models.APP_STATUSES:
            entry = i18n.KEYS.get(f"status.{status}")
            self.assertIsNotNone(entry, f"missing translation for status.{status}")
            self.assertTrue(entry.get("fa"))
            self.assertTrue(entry.get("en"))

    def test_every_asset_status_has_fa_and_en(self):
        for status in models.ASSET_STATUSES:
            entry = i18n.KEYS.get(f"asset.{status}")
            self.assertIsNotNone(entry, f"missing translation for asset.{status}")
            self.assertTrue(entry.get("fa"))
            self.assertTrue(entry.get("en"))

    def test_every_v1_alias_status_covered(self):
        from scanner.models import V1_ALIASES
        for status in V1_ALIASES.values():
            entry = i18n.KEYS.get(f"asset.{status}") or i18n.KEYS.get(f"status.{status.upper()}")
            self.assertIsNotNone(entry, f"missing translation for {status}")

    def test_message_formatting_with_params(self):
        text = i18n.message("warning.dependency_vulns", "fa", count=3)
        self.assertIn("3", text)
        self.assertNotIn("{count}", text)
        text_en = i18n.message("warning.dependency_vulns", "en", count=3)
        self.assertIn("3", text_en)

    def test_unknown_locale_falls_back_to_en(self):
        text = i18n.message("status.SAFE", "xx-not-a-locale")
        self.assertEqual(text, i18n.KEYS["status.SAFE"]["en"])

    def test_unknown_key_returns_key(self):
        self.assertEqual(i18n.message("status.DOES_NOT_EXIST"), "status.DOES_NOT_EXIST")

    def test_translations_file_is_valid_structure(self):
        data = json.loads((Path(i18n._TR_PATH)).read_text(encoding="utf-8"))
        self.assertIn("locales", data)
        for key, entry in data["keys"].items():
            self.assertIsInstance(entry, dict, key)
            self.assertTrue(all(isinstance(v, str) and v.strip() for v in entry.values()), key)


class FakeUpdateClient:
    """Serves a synthetic zip containing two .yar files and one unsafe path."""

    def __init__(self, with_traversal=False):
        self.with_traversal = with_traversal

    def download(self, url, max_bytes):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("repo/master/valid_rules.yar", b'rule community_test { condition: true }')
            z.writestr("repo/master/nested/deep_rules.yar", b'rule community_test2 { condition: true }')
            z.writestr("repo/master/big.yar", b'x' * (4 * 1024 * 1024))
            if self.with_traversal:
                z.writestr("../evil.yar", b'rule evil { condition: true }')
        return buf.getvalue()


class CommunityUpdateTest(unittest.TestCase):
    def test_extracts_only_yar_with_guards(self):
        from scanner.updates import update_community_rules
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "yara-community"
            manifest = update_community_rules(out, Path(tmp) / "manifest.json", FakeUpdateClient())
            names = [p.name for p in out.glob("*.yar")]
            # FakeUpdateClient serves the same 2-file zip for both sources.
            self.assertEqual(len(names), 4, names)
            self.assertTrue(all(n.startswith(("yara-rules-rules__", "signature-base__")) for n in names))
            self.assertEqual(manifest["totalRuleFiles"], 4)
            self.assertTrue(any("big.yar" in s for s in manifest["sources"][0].get("skipped_rule_files", [])))
            self.assertFalse((out / "evil.yar").exists())

    def test_traversal_entry_rejected(self):
        from scanner.updates import update_community_rules
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "yara-community"
            manifest = update_community_rules(out, Path(tmp) / "manifest.json", FakeUpdateClient(with_traversal=True))
            outside = Path(tmp) / "evil.yar"
            self.assertFalse(outside.exists())
            self.assertEqual(manifest["totalRuleFiles"], 4)

    def test_network_failure_keeps_previous_rules(self):
        from scanner.updates import update_community_rules

        class FailingClient:
            def download(self, url, max_bytes):
                raise RuntimeError("offline")

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "yara-community"
            update_community_rules(out, Path(tmp) / "manifest.json", FakeUpdateClient())
            before = sorted(p.name for p in out.glob("*.yar"))
            manifest = update_community_rules(out, Path(tmp) / "manifest.json", FailingClient())
            after = sorted(p.name for p in out.glob("*.yar"))
            self.assertEqual(before, after)  # previous rules untouched
            self.assertEqual(manifest["sources"][0]["status"], "kept_previous")


if __name__ == "__main__":
    unittest.main()
