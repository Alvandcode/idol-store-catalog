import tempfile
import unittest
from pathlib import Path

try:
    import yara as _yara
except ImportError:
    _yara = None

from scanner.engines import yara as yara_engine


@unittest.skipUnless(_yara, "yara-python not installed")
class CommunitySeverityCapTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _write(self, rel, content):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_community_rule_severity_capped_at_medium(self):
        # A third-party rule claims severity "critical": the engine must
        # downgrade it so it can only ever produce a WARNING, not DANGEROUS.
        self._write("built-in/inert.yar", 'rule built_in_inert { strings: $s = "zzz-never-matches" condition: $s }')
        self._write("community/paranoid.yar", '''
rule community_overconfident {
    meta: severity = "critical"
    strings: $s = "hello"
    condition: $s
}
''')
        target = self._write("sample.txt", "hello world")
        result = yara_engine.scan(target, self.root / "built-in", self.root / "community")
        self.assertEqual(result["status"], "detection")
        hit = result["detections"][0]
        self.assertEqual(hit["severity"], "medium", "community severity must be capped")
        self.assertEqual(hit["rule"], "community_overconfident")

    def test_builtin_rules_keep_declared_severity(self):
        self._write("built-in/strict.yar", '''
rule built_in_strict {
    meta: severity = "critical"
    strings: $s = "boom"
    condition: $s
}
''')
        target = self._write("sample2.txt", "boom")
        result = yara_engine.scan(target, self.root / "built-in", None)
        self.assertEqual(result["detections"][0]["severity"], "critical")

    def test_broken_community_rules_do_not_break_scan(self):
        self._write("community/broken.yar", "rule broken { condition: not_valid_syntax }")
        self._write("built-in/fine.yar", 'rule fine { strings: $s = "ok" condition: $s }')
        target = self._write("sample3.txt", "ok")
        result = yara_engine.scan(target, self.root / "built-in", self.root / "community")
        # Built-in rules still work; broken community rules are ignored.
        self.assertEqual(result["status"], "detection")
        self.assertTrue(all(d["rule"] == "fine" for d in result["detections"]))


if __name__ == "__main__":
    unittest.main()
