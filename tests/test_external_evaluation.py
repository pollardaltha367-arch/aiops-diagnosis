import sys
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from evaluate_bgl_task import metrics, record_confusion


class ExternalEvaluationTests(unittest.TestCase):
    def test_confusion_matrix_mapping(self):
        counts = Counter(tp=0, fp=0, fn=0, tn=0)
        record_confusion(counts, True, True)
        record_confusion(counts, False, True)
        record_confusion(counts, True, False)
        record_confusion(counts, False, False)
        self.assertEqual(counts, {"tp": 1, "fp": 1, "fn": 1, "tn": 1})

    def test_binary_metrics(self):
        result = metrics(tp=8, fp=2, fn=2, tn=88)
        self.assertAlmostEqual(result["precision"], 0.8)
        self.assertAlmostEqual(result["recall"], 0.8)
        self.assertAlmostEqual(result["f1"], 0.8)
        self.assertAlmostEqual(result["false_positive_rate"], 2 / 90)


if __name__ == "__main__":
    unittest.main()
