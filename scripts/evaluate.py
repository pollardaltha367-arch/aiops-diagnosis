"""Run the labeled synthetic benchmark and produce reproducible metrics."""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from diagnosis_engine import diagnose


def safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def run(dataset_path: Path) -> dict:
    cases = [json.loads(line) for line in dataset_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    true_positive = false_positive = false_negative = 0
    normal_cases = false_positive_normal = risk_correct = top1 = top3 = 0
    redaction_expected = redaction_found = 0
    durations: list[float] = []
    failures: list[dict] = []

    for case in cases:
        start = time.perf_counter()
        report = diagnose(case["text"], case["source_name"])
        durations.append((time.perf_counter() - start) * 1000)
        expected = set(case["expected_categories"])
        predicted = set(report["category_counts"])
        true_positive += len(expected & predicted)
        false_positive += len(predicted - expected)
        false_negative += len(expected - predicted)
        if not expected:
            normal_cases += 1
            false_positive_normal += int(bool(predicted))
        risk_correct += int(report["summary"]["risk"] == case["expected_risk"])
        ranked = [item["type"] for item in report["hypotheses"] if item["type"] != "未知故障"]
        if expected:
            top1 += int(bool(ranked) and ranked[0] in expected)
            top3 += int(bool(expected.intersection(ranked[:3])))
        for label in case.get("expected_redactions", []):
            redaction_expected += 1
            redaction_found += int(report["redaction"].get(label, 0) > 0)
        if expected != predicted or report["summary"]["risk"] != case["expected_risk"]:
            failures.append({"case_id": case["case_id"], "expected_categories": sorted(expected), "predicted_categories": sorted(predicted), "expected_risk": case["expected_risk"], "predicted_risk": report["summary"]["risk"]})

    precision = safe_div(true_positive, true_positive + false_positive)
    recall = safe_div(true_positive, true_positive + false_negative)
    fault_cases = sum(bool(case["expected_categories"]) for case in cases)
    ordered = sorted(durations)
    p95_index = max(0, min(len(ordered) - 1, int(len(ordered) * 0.95) - 1))
    return {
        "dataset": dataset_path.name, "dataset_source": "synthetic + synthetic-holdout", "cases": len(cases), "fault_cases": fault_cases,
        "precision": precision, "recall": recall, "f1": safe_div(2 * precision * recall, precision + recall),
        "normal_false_positive_rate": safe_div(false_positive_normal, normal_cases),
        "top1_category_hit_rate": safe_div(top1, fault_cases), "top3_category_hit_rate": safe_div(top3, fault_cases),
        "risk_accuracy": safe_div(risk_correct, len(cases)), "redaction_recall": safe_div(redaction_found, redaction_expected),
        "mean_latency_ms": statistics.mean(durations), "p95_latency_ms": ordered[p95_index], "failures": failures,
        "limitations": ["当前评测集为人工构造样例与未参与规则设计的同义表达挑战样例，不能代表企业生产分布。", "根因命中率目前以故障类别为代理指标，不等同于真实根因定位准确率。", "公开数据集与真实故障注入评测尚未完成。"]
    }


def markdown(result: dict) -> str:
    lines = ["# 基准评测报告", "", f"- 数据集：`{result['dataset']}`", f"- 数据来源：{result['dataset_source']}", f"- 样例数：{result['cases']}", f"- 故障样例：{result['fault_cases']}", "", "## 指标", "", "| 指标 | 结果 |", "|---|---:|",
             f"| 分类 Precision | {result['precision']:.3f} |", f"| 分类 Recall | {result['recall']:.3f} |", f"| 分类 F1 | {result['f1']:.3f} |", f"| 正常/恢复样例误报率 | {result['normal_false_positive_rate']:.3f} |", f"| Top-1 类别命中率 | {result['top1_category_hit_rate']:.3f} |", f"| Top-3 类别命中率 | {result['top3_category_hit_rate']:.3f} |", f"| 风险判断准确率 | {result['risk_accuracy']:.3f} |", f"| 脱敏召回率 | {result['redaction_recall']:.3f} |", f"| 平均耗时 | {result['mean_latency_ms']:.3f} ms |", f"| P95 耗时 | {result['p95_latency_ms']:.3f} ms |", "", "## 失败案例", ""]
    if result["failures"]:
        for failure in result["failures"]:
            lines.append(f"- `{failure['case_id']}`：类别 {failure['expected_categories']} → {failure['predicted_categories']}；风险 {failure['expected_risk']} → {failure['predicted_risk']}")
    else:
        lines.append("- 本次人工构造样例未发现失败；仍需使用独立公开数据验证泛化能力。")
    lines += ["", "## 限制", ""] + [f"- {item}" for item in result["limitations"]]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    dataset = ROOT / "datasets" / "benchmark.jsonl"
    output_dir = ROOT / "evaluation"
    output_dir.mkdir(exist_ok=True)
    result = run(dataset)
    (output_dir / "metrics.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    (output_dir / "report.md").write_text(markdown(result), encoding="utf-8")
    print(markdown(result))
