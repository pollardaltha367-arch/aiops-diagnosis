"""Deterministic, evidence-first diagnosis engine for the local AIOps PoC."""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
TIMESTAMP = re.compile(r"(?P<time>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+|Z)?)")
LEVEL = re.compile(r"\b(?P<level>CRITICAL|FATAL|ERROR|WARN(?:ING)?|INFO|DEBUG)\b", re.I)
HOST = re.compile(r"\b(?:host|server|node)[=: ]+(?P<host>[A-Za-z0-9_.-]+)", re.I)
SERVICE = re.compile(r"\bservice[=: ]+(?P<service>[A-Za-z0-9_.-]+)", re.I)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE = re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)")
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
COOKIE = re.compile(r"(?i)\b(?:cookie|set-cookie)\s*[:=]\s*[^\r\n]+")
SECRET = re.compile(r"(?i)(?:\b(?:api[_-]?key|token|password|secret)\b|(?:密码|密钥|令牌))\s*[:=]\s*[^\s,;]+")
AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
CONNECTION_STRING = re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s]+")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.S)
IP_CANDIDATE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])|\b(?:\d{1,3}\.){3}\d{1,3}\b")
RECOVERY_PATTERNS = ("recovered", "resolved", "back to normal", "restored", "恢复正常", "已恢复", "故障解除")
GLOBAL_NEGATIVE_PATTERNS = ("no error", "without error", "not failed", "no failure", "no alerts are active", "未发现异常", "无错误", "无故障")
TEST_PATTERNS = ("test passed", "self-test passed", "health check passed", "测试通过", "演练结束")
STACK_CONTINUATION = re.compile(r"^(?:\s+at\s|\s*File \"|\s*Caused by:|\s*\.\.\. |\s*goroutine |\s*\^|Traceback \(|panic:)")
UNKNOWN_SEVERE = "未知严重事件"


def load_thresholds(path: Path | None = None) -> dict:
    return json.loads((path or ROOT / "config" / "anomaly_thresholds.json").read_text(encoding="utf-8"))


def load_rules(directory: Path | None = None) -> list[dict]:
    rules: list[dict] = []
    for path in sorted((directory or ROOT / "rules").glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError(f"Rule file must contain a list: {path}")
        for rule in data:
            required = {"id", "category", "patterns", "negative_patterns", "severity_weight", "verification", "repair"}
            missing = required.difference(rule)
            if missing:
                raise ValueError(f"Rule {path} missing: {sorted(missing)}")
            rules.append(rule)
    if not rules:
        raise ValueError("No diagnosis rules loaded")
    return rules


RULES = load_rules()
THRESHOLDS = load_thresholds()
SEVERE_LEVELS = set(THRESHOLDS["severe_levels"])


@dataclass
class Event:
    line: int
    end_line: int
    time: str
    level: str
    obj: str
    service: str
    message: str
    stacktrace: list[str]
    categories: list[str]
    state: str
    template: str
    template_id: str
    anomaly_status: str
    classification_status: str
    anomaly_score: int
    score_reasons: list[str]
    occurrences: int = 1


def _replace(text: str, pattern: re.Pattern[str], label: str, value: str, counts: dict[str, int]) -> str:
    def sub(_: re.Match[str]) -> str:
        counts[label] += 1
        return value
    return pattern.sub(sub, text)


def _redact_ips(text: str, counts: dict[str, int]) -> str:
    def sub(match: re.Match[str]) -> str:
        candidate = match.group(0)
        try:
            version = ipaddress.ip_address(candidate).version
        except ValueError:
            return candidate
        label = "ipv4" if version == 4 else "ipv6"
        counts[label] += 1
        return f"[{label.upper()}_REDACTED]"
    return IP_CANDIDATE.sub(sub, text)


def redact(text: str) -> tuple[str, dict[str, int]]:
    """Apply basic local redaction. This is risk reduction, not a compliance guarantee."""
    counts = {name: 0 for name in ("ipv4", "ipv6", "email", "phone", "jwt", "bearer", "cookie", "secret", "cloud_key", "connection_string", "private_key")}
    text = _replace(text, PRIVATE_KEY, "private_key", "[PRIVATE_KEY_REDACTED]", counts)
    text = _replace(text, CONNECTION_STRING, "connection_string", "[CONNECTION_STRING_REDACTED]", counts)
    text = _replace(text, BEARER, "bearer", "Bearer [TOKEN_REDACTED]", counts)
    text = _replace(text, JWT, "jwt", "[JWT_REDACTED]", counts)
    text = _replace(text, COOKIE, "cookie", "cookie=[COOKIE_REDACTED]", counts)
    text = _replace(text, AWS_KEY, "cloud_key", "[CLOUD_KEY_REDACTED]", counts)
    text = _replace(text, EMAIL, "email", "[EMAIL_REDACTED]", counts)
    text = _replace(text, PHONE, "phone", "[PHONE_REDACTED]", counts)
    text = _replace(text, SECRET, "secret", "[SECRET_REDACTED]", counts)
    text = _redact_ips(text, counts)
    return text, counts


def classify(message: str) -> list[str]:
    lowered = message.casefold()
    categories: list[str] = []
    for rule in RULES:
        if any(negative.casefold() in lowered for negative in rule["negative_patterns"]):
            continue
        if any(pattern.casefold() in lowered for pattern in rule["patterns"]):
            categories.append(rule["category"])
    return list(dict.fromkeys(categories))


def normalize_template(message: str) -> str:
    value = TIMESTAMP.sub("<TIME>", message)
    value = re.sub(r"\b(?:[A-Z]\d+)(?:-[A-Z0-9:]+)+\b", "<NODE>", value)
    value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP>", value)
    value = re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}\b", "<UUID>", value)
    value = re.sub(r"\b0x[0-9a-fA-F]+\b", "<HEX>", value)
    value = re.sub(r"(?<![A-Za-z])\d+(?:\.\d+)?(?:ms|s|MB|GB|%)?", "<*>", value)
    return re.sub(r"\s+", " ", value).strip()


def template_id(template: str) -> str:
    return hashlib.sha256(template.encode("utf-8")).hexdigest()[:12]


def _semantic_flags(message: str) -> tuple[bool, bool, bool]:
    lowered = message.casefold()
    recovered = any(pattern in lowered for pattern in RECOVERY_PATTERNS)
    negative = any(pattern in lowered for pattern in GLOBAL_NEGATIVE_PATTERNS)
    test_event = any(pattern in lowered for pattern in TEST_PATTERNS)
    return recovered, negative, test_event


def _base_anomaly_decision(level: str, categories: list[str], message: str) -> tuple[str, str, str, int, list[str]]:
    recovered, negative, test_event = _semantic_flags(message)
    if recovered:
        return "recovered", "not_anomalous", "unclassified", 0, ["恢复语义"]
    if negative:
        return "uncertain", "not_anomalous", "unclassified", 0, ["否定语义"]
    if test_event:
        return "uncertain", "not_anomalous", "unclassified", 0, ["测试或健康检查语义"]

    known = bool(categories)
    score = int(THRESHOLDS["level_scores"].get(level, 0))
    reasons = [f"日志级别:{level}={score}"] if score else []
    if known:
        score += int(THRESHOLDS["known_rule_bonus"])
        reasons.append(f"已知规则命中:+{THRESHOLDS['known_rule_bonus']}")
        return "active", "anomalous", "known", score, reasons
    if level in SEVERE_LEVELS:
        reasons.append("严重级别但未命中已知规则")
        return "active", "anomalous", "unknown", score, reasons
    if level in {"WARN", "WARNING"}:
        return "uncertain", "suspicious", "unknown", score, reasons
    return "uncertain", "not_anomalous", "unclassified", score, reasons


def _structured_rows(text: str, source_name: str) -> list[dict] | None:
    suffix = Path(source_name).suffix.lower()
    if suffix in {".json", ".jsonl"}:
        try:
            data = [json.loads(line) for line in text.splitlines() if line.strip()] if suffix == ".jsonl" else json.loads(text)
            if isinstance(data, dict):
                data = data.get("events", [data])
            return data if isinstance(data, list) and all(isinstance(row, dict) for row in data) else None
        except json.JSONDecodeError:
            return None
    if suffix == ".csv":
        try:
            return list(csv.DictReader(io.StringIO(text)))
        except csv.Error:
            return None
    return None


def _pick(row: dict, names: tuple[str, ...], default: str = "") -> str:
    lowered = {str(key).casefold(): value for key, value in row.items()}
    for name in names:
        value = lowered.get(name.casefold())
        if value not in (None, ""):
            return str(value)
    return default


def _event_from_parts(line: int, end_line: int, message: str, level: str = "", time: str = "", host: str = "", service: str = "", stacktrace: list[str] | None = None) -> Event | None:
    level_match = LEVEL.search(level or message)
    categories = classify(message)
    recovered, negative, test_event = _semantic_flags(message)
    if not level_match and not categories and not recovered and not negative and not test_event:
        return None
    time_match = TIMESTAMP.search(time or message)
    host_match = HOST.search(message)
    service_match = SERVICE.search(message)
    normalized_level = level_match.group("level").upper().replace("WARNING", "WARN") if level_match else "UNKNOWN"
    state, anomaly_status, classification_status, score, score_reasons = _base_anomaly_decision(normalized_level, categories, message)
    if anomaly_status == "anomalous" and classification_status == "unknown":
        categories = [UNKNOWN_SEVERE]
    normalized_template = normalize_template(message)
    return Event(
        line=line, end_line=end_line, time=time_match.group("time") if time_match else (time or "未知"),
        level=normalized_level, obj=host or (host_match.group("host") if host_match else "未知"),
        service=service or (service_match.group("service") if service_match else "未知"),
        message=message[:1000], stacktrace=stacktrace or [], categories=categories or ["未知故障"],
        state=state, template=normalized_template, template_id=template_id(normalized_template),
        anomaly_status=anomaly_status, classification_status=classification_status,
        anomaly_score=score, score_reasons=score_reasons,
    )


def _deduplicate(events: list[Event]) -> list[Event]:
    result: list[Event] = []
    seen: dict[tuple[str, str, str, str], Event] = {}
    for event in events:
        key = (event.level, event.obj, event.service, event.template)
        existing = seen.get(key)
        if existing:
            existing.occurrences += 1
            existing.end_line = max(existing.end_line, event.end_line)
            continue
        seen[key] = event
        result.append(event)
    return result


def build_review_queue(events: list[Event]) -> list[dict]:
    """Aggregate anomalous events into an explainable, read-only review queue."""
    groups: dict[str, list[Event]] = {}
    for event in events:
        if event.anomaly_status == "anomalous":
            groups.setdefault(event.template_id, []).append(event)

    queue: list[dict] = []
    for current_template_id, items in groups.items():
        occurrences = sum(item.occurrences for item in items)
        objects = sorted({item.obj for item in items if item.obj != "未知"})
        services = sorted({item.service for item in items if item.service != "未知"})
        categories = sorted({category for item in items for category in item.categories})
        score = max(item.anomaly_score for item in items)
        reasons = list(dict.fromkeys(reason for item in items for reason in item.score_reasons))
        if occurrences >= int(THRESHOLDS["frequency_high_count"]):
            score += int(THRESHOLDS["frequency_high_bonus"])
            reasons.append(f"模板重复{occurrences}次:+{THRESHOLDS['frequency_high_bonus']}")
        elif occurrences >= int(THRESHOLDS["frequency_medium_count"]):
            score += int(THRESHOLDS["frequency_medium_bonus"])
            reasons.append(f"模板重复{occurrences}次:+{THRESHOLDS['frequency_medium_bonus']}")
        if len(objects) >= int(THRESHOLDS["cross_object_count"]):
            score += int(THRESHOLDS["cross_object_bonus"])
            reasons.append(f"跨{len(objects)}个对象:+{THRESHOLDS['cross_object_bonus']}")
        if score >= int(THRESHOLDS["priority_high_score"]):
            priority = "高"
        elif score >= int(THRESHOLDS["priority_medium_score"]):
            priority = "中"
        else:
            priority = "低"
        queue.append({
            "review_id": f"R-{current_template_id}", "template_id": current_template_id,
            "template": items[0].template, "priority": priority, "anomaly_score": score,
            "score_reasons": reasons, "classification_status": "known" if any(item.classification_status == "known" for item in items) else "unknown",
            "categories": categories, "occurrences": occurrences, "objects": objects[:20], "services": services[:20],
            "first_line": min(item.line for item in items), "last_line": max(item.end_line for item in items),
            "sample_evidence": [item.message for item in items[:3]],
            "required_action": "人工复核并补充指标、变更或拓扑证据；系统不会自动执行修复。",
        })
    return sorted(queue, key=lambda item: (-item["anomaly_score"], -item["occurrences"], item["template_id"]))


def parse_events(text: str, source_name: str = "pasted.log") -> list[Event]:
    rows = _structured_rows(text, source_name)
    events: list[Event] = []
    if rows is not None:
        for number, row in enumerate(rows, 1):
            message = _pick(row, ("message", "detail", "description", "content", "内容", "告警内容"))
            event = _event_from_parts(
                number, number, message,
                _pick(row, ("level", "severity", "status", "级别")),
                _pick(row, ("time", "timestamp", "date", "时间")),
                _pick(row, ("host", "server", "node", "device", "设备")),
                _pick(row, ("service", "service_name", "application", "应用")),
            )
            if event:
                events.append(event)
        return _deduplicate(events)

    lines = text.splitlines()
    number = 0
    while number < len(lines):
        raw = lines[number]
        line = raw.strip()
        if not line:
            number += 1
            continue
        start = number + 1
        stack: list[str] = []
        cursor = number + 1
        if "Traceback (" in line or "Exception" in line or "panic:" in line:
            while cursor < len(lines) and (STACK_CONTINUATION.search(lines[cursor]) or not LEVEL.search(lines[cursor])):
                if lines[cursor].strip():
                    stack.append(lines[cursor].rstrip())
                cursor += 1
        combined = line + ("\n" + "\n".join(stack) if stack else "")
        event = _event_from_parts(start, max(start, cursor), combined, stacktrace=stack)
        if event:
            events.append(event)
        number = max(number + 1, cursor)
    return _deduplicate(events)


def _risk(events: Iterable[Event]) -> tuple[str, str]:
    active = [event for event in events if event.state == "active"]
    critical = sum(event.occurrences for event in active if event.level in {"CRITICAL", "FATAL"})
    errors = sum(event.occurrences for event in active if event.level == "ERROR")
    high_types = {"服务不可用", "数据库异常", "磁盘异常", "网络丢包"}
    high_hits = sum(event.occurrences for event in active if high_types.intersection(event.categories))
    if critical or errors >= 3 or high_hits >= 2:
        return "高", f"检测到 {critical} 条严重事件、{errors} 条 ERROR、{high_hits} 条高影响类别证据。"
    if errors or sum(event.occurrences for event in active) >= 3:
        return "中", f"检测到 {errors} 条 ERROR，共 {sum(event.occurrences for event in active)} 条活动异常，但尚无充分业务中断证据。"
    if active:
        return "低", "仅检测到少量活动异常，当前输入未证明核心业务中断。"
    if events and all(event.state == "recovered" for event in events):
        return "低", "只检测到恢复状态，未发现仍在持续的活动故障证据。"
    return "未知", "未提取到足够的结构化异常事件。"


def diagnose(text: str, source_name: str = "pasted.log") -> dict:
    redacted, redaction_counts = redact(text)
    events = parse_events(redacted, source_name)
    active_events = [event for event in events if event.state == "active"]
    category_counts = Counter(category for event in active_events for category in event.categories for _ in range(event.occurrences) if category != "未知故障")
    rule_map = {rule["category"]: rule for rule in RULES}
    review_queue = build_review_queue(events)
    hypotheses = []
    for category, count in category_counts.most_common(3):
        evidence = [asdict(event) for event in active_events if category in event.categories][:3]
        rule = rule_map.get(category)
        if rule:
            verification = "；".join(rule["verification"]) + "。"
            repair = rule["repair"]
        else:
            verification = "按复核队列检查对应模板、节点、组件、相邻日志、指标和最近变更。"
            repair = "当前异常尚未分类；确认根因前不得自动重启、修改配置或删除数据。"
        hypotheses.append({
            "type": category, "possibility": "中高" if count >= 3 else "中", "evidence_count": count,
            "evidence": evidence, "gap": "缺少对应组件指标、变更记录或下游依赖状态，不能确定唯一根因。",
            "verification": verification, "repair": repair,
        })
    if not hypotheses:
        hypotheses.append({
            "type": "未知故障", "possibility": "低", "evidence_count": 0, "evidence": [],
            "gap": "当前资料缺少仍在持续的、可识别的异常证据。",
            "verification": "补充故障时间窗内的原始日志、受影响服务、监控指标和最近变更记录。",
            "repair": "根因未确认前不执行重启、删除数据或修改生产配置。",
        })
    risk, risk_reason = _risk(events)
    digest = hashlib.sha256(redacted.encode("utf-8")).hexdigest()[:16]
    return {
        "report_id": f"AIOPS-{digest}", "generated_at": datetime.now(timezone.utc).isoformat(), "source": source_name,
        "input_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(), "redaction": redaction_counts,
        "summary": {"lines": len(text.splitlines()), "events": sum(event.occurrences for event in events), "unique_events": len(events), "active_events": sum(event.occurrences for event in active_events), "risk": risk, "risk_reason": risk_reason},
        "events": [asdict(event) for event in events[:50]], "category_counts": dict(category_counts), "hypotheses": hypotheses,
        "review_queue": review_queue,
        "review_summary": {
            "queue_items": len(review_queue), "high_priority": sum(item["priority"] == "高" for item in review_queue),
            "medium_priority": sum(item["priority"] == "中" for item in review_queue), "low_priority": sum(item["priority"] == "低" for item in review_queue),
            "represented_events": sum(item["occurrences"] for item in review_queue),
        },
        "limitations": ["规则匹配结果只用于生成待验证假设。", "基础脱敏用于降低暴露风险，不代表满足合规要求。", "当前版本不连接生产系统，也不自动执行修复命令。"],
    }


def to_markdown(report: dict) -> str:
    summary = report["summary"]
    lines = ["# AIOps 故障诊断报告", "", f"- 报告编号：`{report['report_id']}`", f"- 资料来源：`{report['source']}`", f"- 风险等级：**{summary['risk']}**", "", "## 1. 故障摘要", "", f"共解析 {summary['lines']} 行资料，提取 {summary['events']} 条事件并聚合为 {summary['unique_events']} 个唯一事件。{summary['risk_reason']}", "", "## 2. 异常类型统计", ""]
    lines += [f"- {name}：{count} 条" for name, count in report["category_counts"].items()] or ["- 未识别到活动异常。"]
    lines += ["", "## 3. 关键证据", ""]
    for event in report["events"][:10]:
        lines.append(f"- 第 {event['line']}-{event['end_line']} 行｜{event['time']}｜{event['level']}｜{event['state']}｜出现 {event['occurrences']} 次｜{event['message']}")
    if not report["events"]:
        lines.append("- 当前输入没有足够证据。")
    lines += ["", "## 4. 人工复核队列", ""]
    for item in report.get("review_queue", [])[:20]:
        lines.append(f"- `{item['review_id']}`｜优先级{item['priority']}｜评分{item['anomaly_score']}｜{item['classification_status']}｜{item['occurrences']}次｜{item['template']}")
    if not report.get("review_queue"):
        lines.append("- 当前没有达到复核条件的异常模板。")
    lines += ["", "## 5. 可能根因排序", ""]
    for index, hypothesis in enumerate(report["hypotheses"], 1):
        lines += [f"### {index}. {hypothesis['type']}", "", f"- 可能性：{hypothesis['possibility']}", f"- 支持证据：{hypothesis['evidence_count']} 条", f"- 证据缺口：{hypothesis['gap']}", f"- 最小验证动作：{hypothesis['verification']}", f"- 条件化修复：{hypothesis['repair']}", ""]
    lines += ["## 6. 安全边界", ""] + [f"- {item}" for item in report["limitations"]]
    lines += ["", "## 7. 数据脱敏", ""] + [f"- {name}：{count} 处" for name, count in report["redaction"].items()]
    return "\n".join(lines) + "\n"


def append_audit(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {key: report[key] for key in ("report_id", "generated_at", "source", "input_sha256")}
    entry["risk"] = report["summary"]["risk"]
    entry["events"] = report["summary"]["events"]
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
