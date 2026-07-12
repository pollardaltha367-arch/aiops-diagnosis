import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from diagnosis_engine import diagnose, redact, to_markdown


class DiagnosisEngineTests(unittest.TestCase):
    def test_redacts_sensitive_values(self):
        text, counts = redact("host 10.1.2.3 user=a@b.com token=abc123")
        self.assertNotIn("10.1.2.3", text)
        self.assertNotIn("a@b.com", text)
        self.assertNotIn("abc123", text)
        self.assertEqual(counts, {"ip": 1, "email": 1, "secret": 1})

    def test_database_incident_generates_ranked_hypothesis(self):
        text = "\n".join([
            "2026-07-12 09:00:00 ERROR service=api database connection timeout host=db-01",
            "2026-07-12 09:00:01 ERROR service=api connection pool exhausted host=api-01",
            "2026-07-12 09:00:02 ERROR service=api database connection timeout host=db-01",
        ])
        report = diagnose(text)
        self.assertEqual(report["summary"]["risk"], "高")
        self.assertEqual(report["hypotheses"][0]["type"], "数据库异常")
        self.assertGreaterEqual(report["summary"]["events"], 3)

    def test_unknown_input_is_explicitly_uncertain(self):
        report = diagnose("用户反馈系统偶尔有点慢")
        self.assertEqual(report["summary"]["risk"], "未知")
        self.assertEqual(report["hypotheses"][0]["type"], "未知故障")

    def test_markdown_contains_safety_boundary(self):
        markdown = to_markdown(diagnose("ERROR connection refused host=api-01"))
        self.assertIn("安全边界", markdown)
        self.assertIn("根因排序", markdown)


if __name__ == "__main__":
    unittest.main()
