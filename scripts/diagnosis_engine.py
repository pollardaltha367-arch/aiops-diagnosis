"""Deterministic, evidence-first diagnosis engine for the local AIOps PoC."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


TIMESTAMP = re.compile(r"(?P<time>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})")
LEVEL = re.compile(r"\b(?P<level>CRITICAL|FATAL|ERROR|WARN(?:ING)?|INFO|DEBUG)\b", re.I)
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
TOKEN = re.compile(r"(?i)\b(api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]+")
HOST = re.compile(r"\b(?:host|server|node|service)[=: ]+(?P<host>[A-Za-z0-9_.-]+)", re.I)


RULES = [
    {
        "type": "数据库异常",
        "patterns": ("database connection", "connection pool", "too many connections", "数据库连接失败", "db unavailable"),
        "verify": "检查数据库服务状态、连接池占用、认证错误和数据库错误日志。",
        "repair": "如果确认数据库服务或认证异常，则恢复服务或凭据；如果连接池耗尽，则先定位泄漏再调整容量。",
    },
    {
        "type": "数据库慢查询",
        "patterns": ("slow query", "lock wait", "deadlock", "慢查询", "执行计划"),
        "verify": "检查慢查询日志、执行计划、索引、锁等待和数据库 IOPS。",
        "repair": "如果确认 SQL 或索引导致瓶颈，则优化查询和索引；如果资源饱和，则评估限流或扩容。",
    },
    {
        "type": "网络丢包",
        "patterns": ("packet loss", "丢包", "crc error", "link down", "network unreachable"),
        "verify": "持续采样丢包率和延迟，并检查端口 CRC、drop、error 与 up/down 计数。",
        "repair": "如果确认链路或端口异常，则隔离故障链路并切换到已验证的健康链路。",
    },
    {
        "type": "连接超时",
        "patterns": ("timeout", "timed out", "connection refused", "unreachable", "超时", "不可达"),
        "verify": "对目标主机和端口执行连通性检查，并核对服务监听、防火墙、DNS 与最近网络变更。",
        "repair": "如果确认端口未监听，则恢复目标服务；如果确认访问控制阻断，则按变更流程修正规则。",
    },
    {
        "type": "CPU 资源异常",
        "patterns": ("cpu high", "high cpu", "cpu usage", "cpu过高", "load average"),
        "verify": "检查 CPU 趋势、负载、steal、上下文切换和高占用进程，并对照流量与发布记录。",
        "repair": "如果确认异常进程或版本回归，则保留现场后限流、回滚或优化；容量不足时再扩容。",
    },
    {
        "type": "内存资源异常",
        "patterns": ("out of memory", "oom", "memory high", "内存过高", "memory leak"),
        "verify": "检查内存趋势、swap、OOM 记录、进程占用、堆和 GC 指标。",
        "repair": "如果确认内存泄漏，则修复或回滚对应版本；如果是容量不足，则在验证后扩容。",
    },
    {
        "type": "磁盘异常",
        "patterns": ("disk full", "no space left", "i/o error", "inode", "磁盘异常", "只读文件系统"),
        "verify": "检查磁盘容量、inode、IO 延迟、SMART、挂载状态和异常增长目录。",
        "repair": "如果确认容量耗尽，则按保留策略归档或扩容；如果确认硬件故障，则进入数据恢复和换盘流程。",
    },
    {
        "type": "权限异常",
        "patterns": ("permission denied", "unauthorized", "forbidden", "权限", "access denied"),
        "verify": "核对故障账号、最小权限、凭据有效期和最近权限变更。",
        "repair": "如果确认权限或凭据错误，则按最小权限原则恢复正确授权，不扩大长期权限。",
    },
    {
        "type": "服务不可用",
        "patterns": ("service unavailable", "health check failed", "process exited", "服务不可用", "connection reset"),
        "verify": "检查进程、端口、健康检查、退出码、依赖服务和最近发布。",
        "repair": "如果确认进程退出或发布异常，则先保存现场，再按回滚或恢复流程处理。",
    },
]


@dataclass
class Event:
    line: int
    time: str
    level: str
    obj: str
    message: str
    categories: list[str]


def redact(text: str) -> tuple[str, dict[str, int]]:
    counts = {"ip": 0, "email": 0, "secret": 0}

    def replace(pattern: re.Pattern[str], label: str, value: str) -> str:
        def sub(_: re.Match[str]) -> str:
            counts[label] += 1
            return value
        return pattern.sub(sub, text)

    text = replace(IP, "ip", "[IP_REDACTED]")
    text = replace(EMAIL, "email", "[EMAIL_REDACTED]")
    text = replace(TOKEN, "secret", "[SECRET_REDACTED]")
    return text, counts


def classify(message: str) -> list[str]:
    lowered = message.lower()
    return [rule["type"] for rule in RULES if any(p.lower() in lowered for p in rule["patterns"])]


def parse_events(text: str) -> list[Event]:
    events: list[Event] = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        level_match = LEVEL.search(line)
        categories = classify(line)
        if not level_match and not categories:
            continue
        time_match = TIMESTAMP.search(line)
        host_match = HOST.search(line)
        events.append(Event(
            line=number,
            time=time_match.group("time") if time_match else "未知",
            level=(level_match.group("level").upper().replace("WARNING", "WARN") if level_match else "UNKNOWN"),
            obj=host_match.group("host") if host_match else "未知",
            message=line[:500],
            categories=categories or ["未知故障"],
        ))
    return events


def _risk(events: Iterable[Event]) -> tuple[str, str]:
    events = list(events)
    critical = sum(e.level in {"CRITICAL", "FATAL"} for e in events)
    errors = sum(e.level == "ERROR" for e in events)
    high_types = {"服务不可用", "数据库异常", "磁盘异常", "网络丢包"}
    high_hits = sum(bool(high_types.intersection(e.categories)) for e in events)
    if critical or errors >= 3 or high_hits >= 2:
        return "高", f"检测到 {critical} 条严重事件、{errors} 条 ERROR、{high_hits} 条高影响类别证据。"
    if errors or len(events) >= 3:
        return "中", f"检测到 {errors} 条 ERROR，共 {len(events)} 条异常事件，但尚无充分业务中断证据。"
    if events:
        return "低", "仅检测到少量孤立异常，当前输入未证明核心业务中断。"
    return "未知", "未提取到足够的结构化异常事件。"


def diagnose(text: str, source_name: str = "pasted.log") -> dict:
    redacted, redaction_counts = redact(text)
    events = parse_events(redacted)
    category_counts = Counter(c for event in events for c in event.categories if c != "未知故障")
    rule_map = {rule["type"]: rule for rule in RULES}
    hypotheses = []
    for category, count in category_counts.most_common(3):
        evidence = [asdict(e) for e in events if category in e.categories][:3]
        hypotheses.append({
            "type": category,
            "possibility": "中高" if count >= 3 else "中",
            "evidence_count": count,
            "evidence": evidence,
            "gap": "缺少对应组件指标、变更记录或下游依赖状态，不能确定唯一根因。",
            "verification": rule_map[category]["verify"],
            "repair": rule_map[category]["repair"],
        })
    if not hypotheses:
        hypotheses.append({
            "type": "未知故障", "possibility": "低", "evidence_count": 0, "evidence": [],
            "gap": "当前资料缺少可识别的错误级别、时间、对象或异常模式。",
            "verification": "补充故障时间窗内的原始日志、受影响服务、监控指标和最近变更记录。",
            "repair": "根因未确认前不执行重启、删除数据或修改生产配置。",
        })
    risk, risk_reason = _risk(events)
    digest = hashlib.sha256(redacted.encode("utf-8")).hexdigest()[:16]
    return {
        "report_id": f"AIOPS-{digest}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source_name,
        "input_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "redaction": redaction_counts,
        "summary": {"lines": len(text.splitlines()), "events": len(events), "risk": risk, "risk_reason": risk_reason},
        "events": [asdict(e) for e in events[:50]],
        "category_counts": dict(category_counts),
        "hypotheses": hypotheses,
        "limitations": ["规则匹配结果只用于生成待验证假设。", "当前版本不连接生产系统，也不自动执行修复命令。"],
    }


def to_markdown(report: dict) -> str:
    s = report["summary"]
    lines = [
        "# AIOps 故障诊断报告", "", f"- 报告编号：`{report['report_id']}`",
        f"- 资料来源：`{report['source']}`", f"- 风险等级：**{s['risk']}**", "",
        "## 1. 故障摘要", "", f"共解析 {s['lines']} 行资料，提取 {s['events']} 条异常事件。{s['risk_reason']}", "",
        "## 2. 异常类型统计", "",
    ]
    if report["category_counts"]:
        lines += [f"- {name}：{count} 条" for name, count in report["category_counts"].items()]
    else:
        lines.append("- 未识别到可归类异常。")
    lines += ["", "## 3. 关键证据", ""]
    for event in report["events"][:10]:
        lines.append(f"- 第 {event['line']} 行｜{event['time']}｜{event['level']}｜{event['message']}")
    if not report["events"]:
        lines.append("- 当前输入没有足够证据。")
    lines += ["", "## 4. 可能根因排序", ""]
    for i, h in enumerate(report["hypotheses"], 1):
        lines += [f"### {i}. {h['type']}", "", f"- 可能性：{h['possibility']}",
                  f"- 支持证据：{h['evidence_count']} 条", f"- 证据缺口：{h['gap']}",
                  f"- 最小验证动作：{h['verification']}", f"- 条件化修复：{h['repair']}", ""]
    lines += ["## 5. 安全边界", ""] + [f"- {item}" for item in report["limitations"]]
    lines += ["", "## 6. 数据脱敏", "", f"- IP：{report['redaction']['ip']} 处", f"- 邮箱：{report['redaction']['email']} 处", f"- 密钥字段：{report['redaction']['secret']} 处"]
    return "\n".join(lines) + "\n"


def append_audit(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {k: report[k] for k in ("report_id", "generated_at", "source", "input_sha256")}
    entry["risk"] = report["summary"]["risk"]
    entry["events"] = report["summary"]["events"]
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
