import json
import tempfile
import unittest
from pathlib import Path

from scanner.false_positives import FalsePositiveRegistry
from scanner.models import APP_STATUSES, V1_ALIASES


class ReportModelTest(unittest.TestCase):
    def test_v1_alias_covers_all_statuses(self):
        for status in APP_STATUSES:
            self.assertIn(status, V1_ALIASES)

    def test_dangerous_alias_stays_blocking(self):
        self.assertEqual(V1_ALIASES["DANGEROUS"], "dangerous")

    def test_false_positive_registry_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fp.json"
            path.write_text(json.dumps({
                "reviews": {
                    "0123456789abcdef": {"reviewer": "alvandcode", "decision": "false_positive"}
                }
            }), encoding="utf-8")
            registry = FalsePositiveRegistry(path)
            hit = registry.lookup("0123456789abcdef0000000000000000000000000000000000000000000000000")
            self.assertIsNotNone(hit)
            self.assertEqual(hit["decision"], "false_positive")
            self.assertIsNone(registry.lookup("ffffffff" + "0" * 56))

    def test_registry_tolerates_missing_file(self):
        registry = FalsePositiveRegistry(Path(tempfile.gettempdir()) / "definitely-missing-fp.json")
        self.assertIsNone(registry.lookup("0" * 64))


if __name__ == "__main__":
    unittest.main()
