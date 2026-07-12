import csv
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from triage_file import triage


class TriageFileTests(unittest.TestCase):
    def test_batch_cli_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "incident.log"
            output = root / "out"
            source.write_text("FATAL service=worker heap allocation failure host=node-1", encoding="utf-8")
            summary = triage(source, output)
            self.assertEqual(summary["queue_items"], 1)
            self.assertTrue((output / "report.md").exists())
            self.assertTrue((output / "result.json").exists())
            with (output / "review_queue.csv").open(encoding="utf-8-sig") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(rows[0]["classification_status"], "unknown")
            self.assertIn("人工复核", rows[0]["required_action"])

    def test_size_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "large.log"
            source.write_text("ERROR too large", encoding="utf-8")
            with self.assertRaises(ValueError):
                triage(source, root / "out", max_bytes=2)


if __name__ == "__main__":
    unittest.main()
