# AIOps 故障诊断报告

- 报告编号：`AIOPS-0f921981ad3e5202`
- 资料来源：`BGL_2k.log_structured.csv`
- 风险等级：**高**

## 1. 故障摘要

共解析 2001 行资料，提取 1993 条事件并聚合为 1825 个唯一事件。检测到 347 条严重事件、36 条 ERROR、4 条高影响类别证据。

## 2. 异常类型统计

- 未知严重事件：357 条
- 权限异常：20 条
- 连接超时：9 条
- 服务不可用：4 条

## 3. 关键证据

- 第 1-431 行｜2005-06-03-15.42.50.675872｜INFO｜uncertain｜出现 30 次｜instruction cache parity error corrected
- 第 5-5 行｜2005-06-03-16.47.20.730545｜INFO｜uncertain｜出现 1 次｜63543 double-hummer alignment exceptions
- 第 6-6 行｜2005-06-03-16.56.14.254137｜INFO｜uncertain｜出现 1 次｜162 double-hummer alignment exceptions
- 第 7-7 行｜2005-06-03-16.56.55.309974｜INFO｜uncertain｜出现 1 次｜141 double-hummer alignment exceptions
- 第 8-498 行｜2005-06-03-18.21.59.871925｜INFO｜uncertain｜出现 9 次｜CE sym 2, at 0x0b85eee0, mask 0x05
- 第 9-9 行｜2005-06-04-00.24.32.432192｜FATAL｜active｜出现 1 次｜ciod: failed to read message prefix on control stream (CioStream socket to [IPV4_REDACTED]:33569
- 第 10-10 行｜2005-06-04-00.24.36.222560｜FATAL｜active｜出现 1 次｜ciod: failed to read message prefix on control stream (CioStream socket to [IPV4_REDACTED]:33370
- 第 11-11 行｜2005-06-04-20.28.40.767551｜INFO｜uncertain｜出现 1 次｜CE sym 20, at 0x1438f9e0, mask 0x40
- 第 12-12 行｜2005-06-05-00.09.01.903373｜INFO｜uncertain｜出现 1 次｜generating core.2275
- 第 13-13 行｜2005-06-05-00.09.52.516674｜INFO｜uncertain｜出现 1 次｜generating core.862

## 4. 人工复核队列

- `R-a878b98615b9`｜优先级高｜评分10｜known｜4次｜ciod: Error reading message prefix on CioStream socket to [IPV4_REDACTED]:<*>, Connection reset by peer
- `R-4868bec9d27c`｜优先级高｜评分10｜known｜3次｜ciod: Error loading /p/gb1/stella/UMT2K/<*>/umt2k_DD: invalid or missing program image, Permission denied
- `R-69ca9c631df3`｜优先级高｜评分10｜known｜3次｜ciod: Error loading /home/spelce1/HPCC_IBM/Urgent/COP/<*>K/vnm.rts: invalid or missing program image, Permission denied
- `R-749a7933af64`｜优先级高｜评分8｜unknown｜30次｜data storage interrupt
- `R-98d997a2a483`｜优先级高｜评分8｜unknown｜20次｜instruction address: <HEX>
- `R-eeed8e6a4f19`｜优先级高｜评分8｜unknown｜15次｜ciod: Error loading /bgl/apps/scaletest/performance/MINIBEN/mb_<*>_<*>/allreduce.rts: invalid or missing program image, Exec format error
- `R-12f37a9ad413`｜优先级高｜评分8｜known｜2次｜ciod: Error loading /bgl/apps/followup/SPASM/spasm.<*>: invalid or missing program image, Permission denied
- `R-da08815e470e`｜优先级高｜评分8｜known｜2次｜ciod: Error reading message prefix on CioStream socket to [IPV4_REDACTED]:<*>, Connection timed out
- `R-e7865efae1e1`｜优先级高｜评分8｜known｜2次｜ciod: Error loading /bgl/apps/followup/RAPTOR/pre-study/raptor.newcomp.r1: invalid or missing program image, Permission denied
- `R-05744846e89a`｜优先级高｜评分8｜known｜1次｜ciod: Error loading /home/spelce1/HPCC_IBM/Urgent/COP/<*>K/hpcc-<*>.<*>_opt_essl_cpm: invalid or missing program image, Permission denied
- `R-1b746f36b6ed`｜优先级高｜评分8｜known｜1次｜ciod: Error loading /home/spelce1/HPCC_IBM/Urgent/Gunnels/VNM6<*>/vnm.rts: invalid or missing program image, Permission denied
- `R-5022610e4f4e`｜优先级高｜评分8｜known｜1次｜ciod: Error loading /bgl/apps/followup/SPaSM_static/SPaSM.<*>-<*>: invalid or missing program image, Permission denied
- `R-546cc60cc7d5`｜优先级高｜评分8｜known｜1次｜ciod: Error loading /bgl/apps/SWL/stability/MDCASK/WORK/<*>/inferno: invalid or missing program image, Permission denied
- `R-58e9c488ff0a`｜优先级高｜评分8｜known｜1次｜ciod: Error loading /home/spelce1/HPCC_IBM/Urgent/VNM/<*>K/vnm.rts: invalid or missing program image, Permission denied
- `R-ac6478b29ba4`｜优先级高｜评分8｜known｜1次｜ciod: Error loading /g/g0/spelce1/Tuned/SPaSM-base/rundir/SPaSM.baseline: invalid or missing program image, Permission denied
- `R-dd0745345661`｜优先级高｜评分8｜known｜1次｜ciod: Error creating node map from file /home/pakin1/sweep3d-<*>b/results/random1-<*>x3<*>x3<*>x2.map: Permission denied
- `R-e273a557218b`｜优先级高｜评分8｜known｜1次｜ciod: Error loading /bgl/apps/SWL/stability/NEWS0<*>/news0<*>_DD: invalid or missing program image, Permission denied
- `R-e856ba40f51f`｜优先级高｜评分8｜known｜1次｜ciod: Error loading /p/gb1/stella/SPPM/<*>/sppm_DD: invalid or missing program image, Permission denied
- `R-f67ac313bd06`｜优先级高｜评分8｜known｜1次｜ciod: Error loading /g/g0/spelce1/HPCC_IBM/Urgent/COP/<*>K/RandomAccess.<*>R.rts: invalid or missing program image, Permission denied
- `R-55b26409fbdb`｜优先级中｜评分7｜unknown｜60次｜data TLB error interrupt

## 5. 可能根因排序

### 1. 未知严重事件

- 可能性：中高
- 支持证据：357 条
- 证据缺口：缺少对应组件指标、变更记录或下游依赖状态，不能确定唯一根因。
- 最小验证动作：按复核队列检查对应模板、节点、组件、相邻日志、指标和最近变更。
- 条件化修复：当前异常尚未分类；确认根因前不得自动重启、修改配置或删除数据。

### 2. 权限异常

- 可能性：中高
- 支持证据：20 条
- 证据缺口：缺少对应组件指标、变更记录或下游依赖状态，不能确定唯一根因。
- 最小验证动作：核对故障账号和最小权限；检查凭据有效期和最近权限变更。
- 条件化修复：如果确认权限或凭据错误，则按最小权限原则恢复正确授权，不扩大长期权限。

### 3. 连接超时

- 可能性：中高
- 支持证据：9 条
- 证据缺口：缺少对应组件指标、变更记录或下游依赖状态，不能确定唯一根因。
- 最小验证动作：检查目标主机和端口连通性；核对服务监听、防火墙、DNS 与最近网络变更。
- 条件化修复：如果确认端口未监听，则恢复目标服务；如果确认访问控制阻断，则按变更流程修正规则。

## 6. 安全边界

- 规则匹配结果只用于生成待验证假设。
- 基础脱敏用于降低暴露风险，不代表满足合规要求。
- 当前版本不连接生产系统，也不自动执行修复命令。

## 7. 数据脱敏

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
