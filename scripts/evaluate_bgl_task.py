"""Evaluate open-set log triage on Loghub's labeled BGL 2k sample."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import statistics
import sys
import time
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from diagnosis_engine import UNKNOWN_SEVERE, diagnose, to_markdown


DATASET = ROOT / "datasets" / "external" / "BGL_2k.log_structured.csv"
OUTPUT = ROOT / "real_tasks" / "bgl_2k"
SOURCE_URL = "https://github.com/logpai/loghub/blob/master/BGL/BGL_2k.log_structured.csv"


def div(a: int | float, b: int | float) -> float:
    return a / b if b else 0.0


def metrics(tp: int, fp: int, fn: int, tn: int) -> dict:
    precision = div(tp, tp + fp)
    recall = div(tp, tp + fn)
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall,
        "f1": div(2 * precision * recall, precision + recall),
        "false_positive_rate": div(fp, fp + tn),
        "mcc": div(tp * tn - fp * fn, denominator),
    }


def record_confusion(counts: Counter, truth: bool, predicted: bool) -> None:
    if truth and predicted:
        counts["tp"] += 1
    elif not truth and predicted:
        counts["fp"] += 1
    elif truth and not predicted:
        counts["fn"] += 1
    else:
        counts["tn"] += 1


def _new_counter() -> Counter:
    return Counter(tp=0, fp=0, fn=0, tn=0)


def run() -> dict:
    if not DATASET.exists():
        raise FileNotFoundError("Run scripts/fetch_bgl_sample.py first")
    payload = DATASET.read_bytes()
    text = payload.decode("utf-8")
    rows = list(csv.DictReader(text.splitlines()))

    full_start = time.perf_counter()
    full_report = diagnose(text, DATASET.name)
    full_latency = (time.perf_counter() - full_start) * 1000
    queue_by_template = {item["template_id"]: item for item in full_report["review_queue"]}

    counters = {name: _new_counter() for name in ("v1_rule_only", "v2_open_set", "v3_priority_medium", "v4_priority_high", "severity_reference")}
    predicted_categories: Counter[str] = Counter()
    missed_labels: Counter[str] = Counter()
    missed_templates: Counter[str] = Counter()
    false_positive_templates: Counter[str] = Counter()
    alert_rows_by_template: Counter[str] = Counter()
    durations: list[float] = []
    false_positives: list[dict] = []
    false_negatives: list[dict] = []

    for row in rows:
        event_payload = {
            "timestamp": row["Time"], "level": row["Level"], "host": row["Node"],
            "service": row["Component"], "message": row["Content"],
        }
        start = time.perf_counter()
        report = diagnose(json.dumps(event_payload, ensure_ascii=False), "bgl-event.json")
        durations.append((time.perf_counter() - start) * 1000)
        truth = row["Label"] != "-"
        categories = set(report["category_counts"])
        event = report["events"][0] if report["events"] else None
        current_template_id = event["template_id"] if event else ""
        queue_item = queue_by_template.get(current_template_id)

        predictions = {
            "v1_rule_only": any(category != UNKNOWN_SEVERE for category in categories),
            "v2_open_set": bool(categories),
            "v3_priority_medium": bool(queue_item and queue_item["priority"] in {"高", "中"}),
            "v4_priority_high": bool(queue_item and queue_item["priority"] == "高"),
            "severity_reference": row["Level"].upper() in {"ERROR", "FATAL", "SEVERE", "CRITICAL"},
        }
        for name, predicted in predictions.items():
            record_confusion(counters[name], truth, predicted)
        predicted_categories.update(report["category_counts"])
        if truth:
            alert_rows_by_template[current_template_id] += 1
        if truth and not predictions["v2_open_set"]:
            missed_labels[row["Label"]] += 1
            missed_templates[row["EventTemplate"]] += 1
            false_negatives.append({
                "line_id": row["LineId"], "official_label": row["Label"], "predicted_label": "normal_or_uncertain",
                "log_level": row["Level"], "message": row["Content"], "template_id": current_template_id,
                "rule_hit": False, "error_reason": "open_set_not_triggered", "recommended_fix": "检查级别解析、否定/恢复过滤和模板异常证据",
            })
        if not truth and predictions["v2_open_set"]:
            false_positive_templates[row["EventTemplate"]] += 1
            false_positives.append({
                "line_id": row["LineId"], "official_label": row["Label"], "predicted_label": ",".join(sorted(categories)),
                "log_level": row["Level"], "message": row["Content"], "template_id": current_template_id,
                "rule_hit": any(category != UNKNOWN_SEVERE for category in categories),
                "error_reason": "label_definition_or_severe_level_false_positive",
                "recommended_fix": "人工复核该模板；结合历史正常模板、上下文和组件知识降低误报",
            })

    ablation = {name: metrics(**counts) for name, counts in counters.items()}
    ordered = sorted(durations)
    p95 = ordered[max(0, int(len(ordered) * 0.95) - 1)]
    top10 = full_report["review_queue"][:10]
    top10_alerts = sum(alert_rows_by_template[item["template_id"]] for item in top10)
    total_templates = len({row["EventTemplate"] for row in rows})
    return {
        "task": "BGL 2k open-set alert triage and evidence review queue",
        "source_url": SOURCE_URL, "source_repository": "https://github.com/logpai/loghub",
        "dataset_sha256": hashlib.sha256(payload).hexdigest(),
        "rows": len(rows), "alerts": sum(row["Label"] != "-" for row in rows), "normal": sum(row["Label"] == "-" for row in rows),
        "ablation": ablation,
        "project_active_category_detection": ablation["v1_rule_only"],
        "open_set_detection": ablation["v2_open_set"],
        "severity_only_reference": ablation["severity_reference"],
        "review_queue": {
            **full_report["review_summary"], "total_input_rows": len(rows), "total_templates": total_templates,
            "row_to_queue_reduction": 1 - div(full_report["review_summary"]["queue_items"], len(rows)),
            "top10_alert_coverage": div(top10_alerts, sum(row["Label"] != "-" for row in rows)),
        },
        "predicted_categories": dict(predicted_categories),
        "top_missed_labels": missed_labels.most_common(10), "top_missed_templates": missed_templates.most_common(10),
        "top_false_positive_templates": false_positive_templates.most_common(10),
        "per_row_mean_latency_ms": statistics.mean(durations), "per_row_p95_latency_ms": p95,
        "full_file_latency_ms": full_latency, "full_diagnosis": full_report,
        "_false_positives": false_positives, "_false_negatives": false_negatives,
        "limitations": [
            "BGL是超算领域日志，当前规则面向通用服务器、网络、数据库和应用故障，属于领域外评测。",
            "BGL标签表示alert/non-alert，不等同于本项目的根因类别标签。",
            "模板评分阈值为工程初始值，尚未在企业历史数据上校准。",
            "复核队列只做只读分流，不自动执行修复。",
        ],
    }


def pct(value: float) -> str:
    return f"{value:.3f}"


def render(result: dict) -> str:
    lines = [
        "# BGL 2K 开放集日志初筛任务报告", "", "## 1. 企业任务定义", "",
        "将2,000行批量日志压缩为可解释的人工复核队列：已知故障继续分类，未命中规则的严重日志进入“未知严重事件”，再按级别、模板重复和跨对象传播进行优先级排序。系统全程只读，不执行修复。", "",
        "## 2. 数据", "", f"- 来源：[{result['source_url']}]({result['source_url']})",
        f"- 样本：{result['rows']}行，其中告警{result['alerts']}行、非告警{result['normal']}行",
        f"- SHA-256：`{result['dataset_sha256']}`", "- 第一列为`-`时表示非告警，其他标签表示告警。", "",
        "## 3. 消融实验", "", "| 版本 | Precision | Recall | F1 | FPR | MCC | TP / FP / FN / TN |", "|---|---:|---:|---:|---:|---:|---:|",
    ]
    labels = {
        "v1_rule_only": "V1 仅已知规则", "v2_open_set": "V2 +未知严重事件",
        "v3_priority_medium": "V3 +模板中高优先级", "v4_priority_high": "V4 仅高优先级",
        "severity_reference": "严重级别参考基线",
    }
    for name, label in labels.items():
        value = result["ablation"][name]
        lines.append(f"| {label} | {pct(value['precision'])} | {pct(value['recall'])} | {pct(value['f1'])} | {pct(value['false_positive_rate'])} | {pct(value['mcc'])} | {value['tp']} / {value['fp']} / {value['fn']} / {value['tn']} |")
    queue = result["review_queue"]
    lines += ["", "## 4. 人工复核工作量", "",
              f"- 原始日志：{queue['total_input_rows']}行，{queue['total_templates']}个官方模板",
              f"- 项目复核队列：{queue['queue_items']}个模板簇，其中高优先级{queue['high_priority']}、中优先级{queue['medium_priority']}、低优先级{queue['low_priority']}",
              f"- 行到复核项压缩率：{queue['row_to_queue_reduction']:.1%}",
              f"- 前10个复核项覆盖官方告警：{queue['top10_alert_coverage']:.1%}", "",
              "## 5. 性能", "", f"- 逐行平均：{result['per_row_mean_latency_ms']:.3f} ms",
              f"- 逐行P95：{result['per_row_p95_latency_ms']:.3f} ms", f"- 完整CSV：{result['full_file_latency_ms']:.3f} ms", "",
              "## 6. 主要误报模板", ""]
    lines += [f"- {count}行：`{template}`" for template, count in result["top_false_positive_templates"]] or ["- 无"]
    lines += ["", "## 7. 结论", "",
              "未知严重事件通道解决了“未命中规则就完全漏掉”的问题；模板聚合把逐行告警转化为有限的复核项，并保留评分原因、对象、组件和样例证据。它现在能承担企业日志初筛与值班分流，但仍不能代替根因确认。",
              "", "高召回带来的误报必须通过企业历史正常模板、组件知识、上下文窗口和阈值校准继续降低。不能把本次BGL结果宣传为企业生产准确率。", "",
              "## 8. 限制", ""]
    lines += [f"- {item}" for item in result["limitations"]]
    lines += ["", "## 9. 来源", "", "- Loghub：https://github.com/logpai/loghub", "- BGL说明：https://github.com/logpai/loghub/tree/master/BGL", "- Jieming Zhu等，《Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics》，ISSRE 2023。"]
    return "\n".join(lines) + "\n"


def write_failures(path: Path, rows: list[dict]) -> None:
    fields = ["line_id", "official_label", "predicted_label", "log_level", "message", "template_id", "rule_hit", "error_reason", "recommended_fix"]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    OUTPUT.mkdir(parents=True, exist_ok=True)
    analysis = OUTPUT / "analysis"
    analysis.mkdir(exist_ok=True)
    result = run()
    write_failures(analysis / "false_positives.csv", result.pop("_false_positives"))
    write_failures(analysis / "false_negatives.csv", result.pop("_false_negatives"))
    (OUTPUT / "metrics.json").write_text(json.dumps({key: value for key, value in result.items() if key != "full_diagnosis"}, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUTPUT / "diagnosis.md").write_text(to_markdown(result["full_diagnosis"]), encoding="utf-8")
    report = render(result)
    (OUTPUT / "report.md").write_text(report, encoding="utf-8")
    print(report)
