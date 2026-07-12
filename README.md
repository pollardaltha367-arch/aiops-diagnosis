# AIOps 证据链故障诊断助手

一个本地运行、只读安全的 AIOps 诊断 PoC。它从日志或故障描述中提取异常事件，进行敏感信息脱敏，形成基于证据的风险判断、根因假设、验证动作和 Markdown 诊断报告。

## 当前能力

- 粘贴日志或读取 `.log`、`.txt`、`.csv` 文本文件
- 对 IP、邮箱和常见密钥字段进行脱敏
- 提取 ERROR、WARN、CRITICAL 等异常事件
- 识别数据库、网络、CPU、内存、磁盘、权限和服务异常
- 输出风险等级、关键证据和 Top-3 待验证根因
- 生成条件化修复建议并导出 Markdown 报告
- 写入不包含原始日志的本地审计记录
- 提供零第三方依赖的本地 Web 页面

## 快速启动

需要 Python 3.10 或更高版本。

```powershell
py -3 scripts/server.py
```

浏览器访问 `http://127.0.0.1:8765`。

## 测试

```powershell
py -3 -m unittest discover -s tests -v
```

## 安全边界

当前版本只生成诊断建议，不连接生产系统，不自动执行排查或修复命令。规则匹配只用于形成待验证假设，不能替代运维人员确认。

## 项目结构

```text
assets/web/                 本地 Web 界面
scripts/diagnosis_engine.py 诊断、脱敏与报告引擎
scripts/server.py           本地 HTTP 服务
tests/                      自动化测试
references/                 故障知识、报告模板与检查清单
SKILL.md                    Codex Skill 工作流
```

## 当前阶段

该项目处于可运行 MVP 阶段，适合本地演示、教学和低风险 PoC。企业试点前仍需要真实数据评测、身份权限、持久化数据库、监控平台接入、部署与合规建设。
