import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from diagnosis_engine import RULES, UNKNOWN_SEVERE, diagnose, normalize_template, parse_events, redact, to_markdown


class DiagnosisEngineTests(unittest.TestCase):
    def test_rules_are_loaded_from_configuration(self):
        self.assertGreaterEqual(len(RULES), 9)
        self.assertTrue(all(rule["id"] and rule["verification"] for rule in RULES))

    def test_redacts_basic_sensitive_values(self):
        text, counts = redact("host 10.1.2.3 user=a@b.com token=abc123 phone=13812345678")
        for value in ("10.1.2.3", "a@b.com", "abc123", "13812345678"):
            self.assertNotIn(value, text)
        self.assertEqual(counts["ipv4"], 1)
        self.assertEqual(counts["email"], 1)
        self.assertEqual(counts["secret"], 1)
        self.assertEqual(counts["phone"], 1)

    def test_redacts_advanced_secrets(self):
        raw = "Bearer eyJabc.def.ghi mongodb://admin:pass@db/app AKIAIOSFODNN7EXAMPLE 2001:db8::1"
        text, counts = redact(raw)
        self.assertNotIn("admin:pass", text)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", text)
        self.assertNotIn("2001:db8::1", text)
        self.assertEqual(counts["bearer"], 1)
        self.assertEqual(counts["connection_string"], 1)
        self.assertEqual(counts["cloud_key"], 1)
        self.assertEqual(counts["ipv6"], 1)

    def test_database_incident_generates_ranked_hypothesis(self):
        text = "\n".join([
            "2026-07-12 09:00:00 ERROR service=api database connection timeout host=db-01",
            "2026-07-12 09:00:01 ERROR service=api connection pool exhausted host=api-01",
            "2026-07-12 09:00:02 ERROR service=api too many connections host=db-01",
        ])
        report = diagnose(text)
        self.assertEqual(report["summary"]["risk"], "高")
        self.assertEqual(report["hypotheses"][0]["type"], "数据库异常")

    def test_recovered_event_is_not_active_root_cause(self):
        report = diagnose("2026-07-12 09:00:00 INFO service=db database connection recovered")
        self.assertEqual(report["events"][0]["state"], "recovered")
        self.assertEqual(report["summary"]["active_events"], 0)
        self.assertEqual(report["hypotheses"][0]["type"], "未知故障")

    def test_negative_expression_is_not_fault(self):
        report = diagnose("2026-07-12 09:00:00 INFO service=api no timeout detected")
        self.assertEqual(report["category_counts"], {})
        self.assertEqual(report["summary"]["risk"], "未知")

    def test_duplicate_events_are_aggregated(self):
        text = "\n".join([
            "2026-07-12 09:00:00 ERROR service=api connection refused host=db-01",
            "2026-07-12 09:00:01 ERROR service=api connection refused host=db-01",
        ])
        report = diagnose(text)
        self.assertEqual(report["summary"]["events"], 2)
        self.assertEqual(report["summary"]["unique_events"], 1)
        self.assertEqual(report["events"][0]["occurrences"], 2)

    def test_json_event_parsing(self):
        payload = json.dumps({"timestamp": "2026-07-12T09:00:00Z", "level": "ERROR", "service": "order", "host": "node-1", "message": "database connection timeout"})
        event = parse_events(payload, "incident.json")[0]
        self.assertEqual(event.service, "order")
        self.assertEqual(event.obj, "node-1")
        self.assertIn("数据库异常", event.categories)

    def test_csv_field_alias_parsing(self):
        payload = "时间,级别,设备,内容\n2026-07-12 09:00:00,WARN,node-1,CPU过高"
        event = parse_events(payload, "alerts.csv")[0]
        self.assertEqual(event.obj, "node-1")
        self.assertIn("CPU 资源异常", event.categories)

    def test_multiline_traceback_is_one_event(self):
        payload = "ERROR service=api Exception database connection timeout\nTraceback (most recent call last):\n  File \"app.py\", line 8\nRuntimeError: failed"
        events = parse_events(payload)
        self.assertEqual(len(events), 1)
        self.assertGreaterEqual(events[0].end_line, 3)

    def test_unknown_input_is_explicitly_uncertain(self):
        report = diagnose("用户反馈系统偶尔有点慢")
        self.assertEqual(report["summary"]["risk"], "未知")
        self.assertEqual(report["hypotheses"][0]["type"], "未知故障")

    def test_unknown_severe_event_enters_review_queue(self):
        report = diagnose("FATAL service=worker heap allocation failure host=node-1")
        event = report["events"][0]
        self.assertEqual(event["anomaly_status"], "anomalous")
        self.assertEqual(event["classification_status"], "unknown")
        self.assertIn(UNKNOWN_SEVERE, event["categories"])
        self.assertEqual(report["review_summary"]["queue_items"], 1)

    def test_negative_severe_event_is_filtered(self):
        report = diagnose("ERROR service=api no error detected; health check passed")
        self.assertEqual(report["summary"]["active_events"], 0)
        self.assertEqual(report["review_summary"]["queue_items"], 0)

    def test_template_id_is_stable_across_dynamic_values(self):
        first = parse_events("ERROR service=api connection refused host=node-1 request 123")[0]
        second = parse_events("ERROR service=api connection refused host=node-1 request 456")[0]
        self.assertEqual(first.template_id, second.template_id)
        self.assertEqual(normalize_template("request 123"), normalize_template("request 456"))

    def test_review_queue_aggregates_and_scores_templates(self):
        text = "\n".join(f"FATAL service=worker heap allocation failure host=node-{index}" for index in range(1, 5))
        report = diagnose(text)
        item = report["review_queue"][0]
        self.assertEqual(item["occurrences"], 4)
        self.assertEqual(len(item["objects"]), 4)
        self.assertGreaterEqual(item["anomaly_score"], 7)

    def test_markdown_contains_safety_boundary(self):
        markdown = to_markdown(diagnose("ERROR connection refused host=api-01"))
        self.assertIn("安全边界", markdown)
        self.assertIn("不代表满足合规要求", markdown)
        self.assertIn("人工复核队列", markdown)


if __name__ == "__main__":
    unittest.main()
