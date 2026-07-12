# AIOps 故障诊断报告

- 报告编号：`AIOPS-0f921981ad3e5202`
- 资料来源：`BGL_2k.log_structured.csv`
- 风险等级：**高**

## 1. 故障摘要

共解析 2001 行资料，提取 1993 条事件并聚合为 1825 个唯一事件。检测到 26 条严重事件、0 条 ERROR、4 条高影响类别证据。

## 2. 异常类型统计

- 权限异常：20 条
- 连接超时：9 条
- 服务不可用：4 条

## 3. 关键证据

- 第 1-431 行｜2005-06-03-15.42.50.675872｜INFO｜uncertain｜出现 30 次｜instruction cache parity error corrected
- 第 5-5 行｜2005-06-03-16.47.20.730545｜INFO｜uncertain｜出现 1 次｜63543 double-hummer alignment exceptions
- 第 6-6 行｜2005-06-03-16.56.14.254137｜INFO｜uncertain｜出现 1 次｜162 double-hummer alignment exceptions
- 第 7-7 行｜2005-06-03-16.56.55.309974｜INFO｜uncertain｜出现 1 次｜141 double-hummer alignment exceptions
- 第 8-498 行｜2005-06-03-18.21.59.871925｜INFO｜uncertain｜出现 9 次｜CE sym 2, at 0x0b85eee0, mask 0x05
- 第 9-9 行｜2005-06-04-00.24.32.432192｜FATAL｜uncertain｜出现 1 次｜ciod: failed to read message prefix on control stream (CioStream socket to [IPV4_REDACTED]:33569
- 第 10-10 行｜2005-06-04-00.24.36.222560｜FATAL｜uncertain｜出现 1 次｜ciod: failed to read message prefix on control stream (CioStream socket to [IPV4_REDACTED]:33370
- 第 11-11 行｜2005-06-04-20.28.40.767551｜INFO｜uncertain｜出现 1 次｜CE sym 20, at 0x1438f9e0, mask 0x40
- 第 12-12 行｜2005-06-05-00.09.01.903373｜INFO｜uncertain｜出现 1 次｜generating core.2275
- 第 13-13 行｜2005-06-05-00.09.52.516674｜INFO｜uncertain｜出现 1 次｜generating core.862

## 4. 可能根因排序

### 1. 权限异常

- 可能性：中高
- 支持证据：20 条
- 证据缺口：缺少对应组件指标、变更记录或下游依赖状态，不能确定唯一根因。
- 最小验证动作：核对故障账号和最小权限；检查凭据有效期和最近权限变更。
- 条件化修复：如果确认权限或凭据错误，则按最小权限原则恢复正确授权，不扩大长期权限。

### 2. 连接超时

- 可能性：中高
- 支持证据：9 条
- 证据缺口：缺少对应组件指标、变更记录或下游依赖状态，不能确定唯一根因。
- 最小验证动作：检查目标主机和端口连通性；核对服务监听、防火墙、DNS 与最近网络变更。
- 条件化修复：如果确认端口未监听，则恢复目标服务；如果确认访问控制阻断，则按变更流程修正规则。

### 3. 服务不可用

- 可能性：中高
- 支持证据：4 条
- 证据缺口：缺少对应组件指标、变更记录或下游依赖状态，不能确定唯一根因。
- 最小验证动作：检查进程、端口、健康检查和退出码；检查依赖服务和最近发布。
- 条件化修复：如果确认进程退出或发布异常，则先保存现场，再按回滚或恢复流程处理。

## 5. 安全边界

- 规则匹配结果只用于生成待验证假设。
- 基础脱敏用于降低暴露风险，不代表满足合规要求。
- 当前版本不连接生产系统，也不自动执行修复命令。

## 6. 数据脱敏

- ipv4：36 处
- ipv6：0 处
- email：0 处
- phone：0 处
- jwt：0 处
- bearer：0 处
- cookie：0 处
- secret：0 处
- cloud_key：0 处
- connection_string：0 处
- private_key：0 处
