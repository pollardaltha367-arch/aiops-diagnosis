"""Evaluate the diagnosis project on Loghub's labeled BGL 2k sample."""

from __future__ import annotations

import csv
import hashlib
import json
import statistics
import sys
import time
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from diagnosis_engine import diagnose, to_markdown


DATASET = ROOT / "datasets" / "external" / "BGL_2k.log_structured.csv"
OUTPUT = ROOT / "real_tasks" / "bgl_2k"
SOURCE_URL = "https://github.com/logpai/loghub/blob/master/BGL/BGL_2k.log_structured.csv"


def div(a: int | float, b: int | float) -> float:
    return a / b if b else 0.0


def metrics(tp: int, fp: int, fn: int, tn: int) -> dict:
    precision = div(tp, tp + fp)
    recall = div(tp, tp + fn)
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall,
        "f1": div(2 * precision * recall, precision + recall),
        "false_positive_rate": div(fp, fp + tn),
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


def run() -> dict:
    if not DATASET.exists():
        raise FileNotFoundError("Run scripts/fetch_bgl_sample.py first")
    payload = DATASET.read_bytes()
    rows = list(csv.DictReader(payload.decode("utf-8").splitlines()))
    project_counts = Counter(tp=0, fp=0, fn=0, tn=0)
    severity_counts = Counter(tp=0, fp=0, fn=0, tn=0)
    predicted_categories: Counter[str] = Counter()
    missed_labels: Counter[str] = Counter()
    missed_templates: Counter[str] = Counter()
    false_positive_templates: Counter[str] = Counter()
    durations: list[float] = []

    for row in rows:
        event = {
            "timestamp": row["Time"], "level": row["Level"], "host": row["Node"],
            "service": row["Component"], "message": row["Content"],
        }
        start = time.perf_counter()
        report = diagnose(json.dumps(event, ensure_ascii=False), "bgl-event.json")
        durations.append((time.perf_counter() - start) * 1000)
        truth = row["Label"] != "-"
        predicted = bool(report["category_counts"])
        severity_predicted = row["Level"].upper() in {"ERROR", "FATAL", "SEVERE", "CRITICAL"}
        record_confusion(project_counts, truth, predicted)
        record_confusion(severity_counts, truth, severity_predicted)
        predicted_categories.update(report["category_counts"])
        if truth and not predicted:
            missed_labels[row["Label"]] += 1
            missed_templates[row["EventTemplate"]] += 1
        if not truth and predicted:
            false_positive_templates[row["EventTemplate"]] += 1

    project = metrics(**project_counts)
    severity = metrics(**severity_counts)
    ordered = sorted(durations)
    p95 = ordered[max(0, int(len(ordered) * 0.95) - 1)]
    full_start = time.perf_counter()
    full_report = diagnose(payload.decode("utf-8"), DATASET.name)
    full_latency = (time.perf_counter() - full_start) * 1000
    return {
        "task": "BGL 2k labeled alert detection and evidence diagnosis",
        "source_url": SOURCE_URL,
        "source_repository": "https://github.com/logpai/loghub",
        "dataset_sha256": hashlib.sha256(payload).hexdigest(),
        "rows": len(rows), "alerts": sum(row["Label"] != "-" for row in rows),
        "normal": sum(row["Label"] == "-" for row in rows),
        "project_active_category_detection": project,
        "severity_only_reference": severity,
        "predicted_categories": dict(predicted_categories),
        "top_missed_labels": missed_labels.most_common(10),
        "top_missed_templates": missed_templates.most_common(10),
        "top_false_positive_templates": false_positive_templates.most_common(10),
        "per_row_mean_latency_ms": statistics.mean(durations),
        "per_row_p95_latency_ms": p95,
        "full_file_latency_ms": full_latency,
        "full_diagnosis": full_report,
        "limitations": [
            "BGL是超算领域日志，当前规则面向通用服务器、网络、数据库和应用故障，属于明显的领域外评测。",
            "BGL标签表示alert/non-alert，不等同于本项目的根因类别标签。",
            "severity-only仅作为参考基线，不是项目新增算法。",
        ],
    }


def pct(value: float) -> str:
    return f"{value:.3f}"


def render(result: dict) -> str:
    project = result["project_active_category_detection"]
    baseline = result["severity_only_reference"]
    lines = [
        "# BGL 2K 真实公开日志任务报告", "",
        "## 1. 任务", "",
        "使用AIOps证据链故障诊断助手分析Loghub公开的BGL 2,000行结构化日志样本，验证项目在未参与规则设计的真实超算日志上的告警发现能力、误报、漏报和处理耗时。", "",
        "## 2. 数据", "",
        f"- 来源：[{result['source_url']}]({result['source_url']})",
        f"- 样本：{result['rows']}行，其中告警{result['alerts']}行、非告警{result['normal']}行",
        f"- SHA-256：`{result['dataset_sha256']}`",
        "- 标签规则：第一列为`-`时表示非告警，其他标签表示告警。", "",
        "## 3. 验收指标", "",
        "| 方法 | Precision | Recall | F1 | 误报率 | TP / FP / FN / TN |", "|---|---:|---:|---:|---:|---:|",
        f"| 当前项目：活动故障类别 | {pct(project['precision'])} | {pct(project['recall'])} | {pct(project['f1'])} | {pct(project['false_positive_rate'])} | {project['tp']} / {project['fp']} / {project['fn']} / {project['tn']} |",
        f"| 日志级别参考基线 | {pct(baseline['precision'])} | {pct(baseline['recall'])} | {pct(baseline['f1'])} | {pct(baseline['false_positive_rate'])} | {baseline['tp']} / {baseline['fp']} / {baseline['fn']} / {baseline['tn']} |", "",
        "## 4. 性能", "",
        f"- 逐行平均诊断耗时：{result['per_row_mean_latency_ms']:.3f} ms",
        f"- 逐行P95诊断耗时：{result['per_row_p95_latency_ms']:.3f} ms",
        f"- 完整CSV分析耗时：{result['full_file_latency_ms']:.3f} ms", "",
        "## 5. 项目识别到的类别", "",
    ]
    lines += [f"- {name}：{count}" for name, count in result["predicted_categories"].items()] or ["- 未识别到当前规则覆盖的活动故障类别。"]
    lines += ["", "## 6. 主要漏报", "", "### 官方告警标签", ""]
    lines += [f"- `{name}`：{count}行" for name, count in result["top_missed_labels"]]
    lines += ["", "### 日志模板", ""]
    lines += [f"- {count}行：`{template}`" for template, count in result["top_missed_templates"]]
    lines += ["", "## 7. 结论", "",
              "本次任务证明项目可以稳定读取真实结构化CSV、完成字段映射、事件聚合和报告生成，但当前九类关键词规则不能泛化为通用日志异常检测器。其主要价值仍是对已覆盖通用故障表达生成证据链，而不是发现BGL领域中的未知内核异常。",
              "", "日志级别参考基线在BGL上也会产生明显误报，说明仅依赖FATAL/ERROR同样不足。下一步应增加“未知严重事件”通道、模板频次异常检测和领域适配规则，并用独立数据复测，而不是把BGL标签直接硬编码进现有规则。", "",
              "## 8. 限制", ""]
    lines += [f"- {item}" for item in result["limitations"]]
    lines += ["", "## 9. 来源", "", "- Loghub数据仓库：https://github.com/logpai/loghub", "- BGL样本与标签说明：https://github.com/logpai/loghub/tree/master/BGL", "- Jieming Zhu等，《Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics》，ISSRE 2023。"]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    OUTPUT.mkdir(parents=True, exist_ok=True)
    result = run()
    (OUTPUT / "metrics.json").write_text(json.dumps({key: value for key, value in result.items() if key != "full_diagnosis"}, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUTPUT / "diagnosis.md").write_text(to_markdown(result["full_diagnosis"]), encoding="utf-8")
    report = render(result)
    (OUTPUT / "report.md").write_text(report, encoding="utf-8")
    print(report)
