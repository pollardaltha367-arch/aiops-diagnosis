# BGL 2K 真实公开日志任务报告

## 1. 任务

使用AIOps证据链故障诊断助手分析Loghub公开的BGL 2,000行结构化日志样本，验证项目在未参与规则设计的真实超算日志上的告警发现能力、误报、漏报和处理耗时。

## 2. 数据

- 来源：[https://github.com/logpai/loghub/blob/master/BGL/BGL_2k.log_structured.csv](https://github.com/logpai/loghub/blob/master/BGL/BGL_2k.log_structured.csv)
- 样本：2000行，其中告警143行、非告警1857行
- SHA-256：`3fe74103c0b02a28514534e2a47257a3f770135ca61afd425bbd3b9d6a31fe26`
- 标签规则：第一列为`-`时表示非告警，其他标签表示告警。

## 3. 验收指标

| 方法 | Precision | Recall | F1 | 误报率 | TP / FP / FN / TN |
|---|---:|---:|---:|---:|---:|
| 当前项目：活动故障类别 | 0.182 | 0.042 | 0.068 | 0.015 | 6 / 27 / 137 / 1830 |
| 日志级别参考基线 | 0.362 | 1.000 | 0.532 | 0.136 | 143 / 252 / 0 / 1605 |

## 4. 性能

- 逐行平均诊断耗时：0.297 ms
- 逐行P95诊断耗时：0.537 ms
- 完整CSV分析耗时：415.359 ms

## 5. 项目识别到的类别

- 权限异常：20
- 连接超时：9
- 服务不可用：4

## 6. 主要漏报

### 官方告警标签

- `KERNDTLB`：60行
- `KERNSTOR`：30行
- `APPSEV`：17行
- `KERNMNTF`：11行
- `KERNTERM`：7行
- `KERNREC`：5行
- `APPREAD`：3行
- `KERNRTSP`：2行
- `APPCHILD`：1行
- `APPOUT`：1行

### 日志模板

- 60行：`data TLB error interrupt`
- 30行：`data storage interrupt`
- 9行：`ciod: Error reading message prefix after LOAD_MESSAGE on CioStream socket to <*>:<*>: Link has been severed`
- 9行：`Lustre mount FAILED : bglio<*> : point <*>`
- 8行：`ciod: Error reading message prefix on CioStream socket to <*>:<*>, Link has been severed`
- 6行：`rts: kernel terminated for reason <*>`
- 5行：`Error receiving packet on tree network, expecting type <*> instead of type <*> (softheader=<*> <*> <*> <*>) PSR0=<*> PSR1=<*> PRXF=<*> PIXF=<*>`
- 3行：`ciod: failed to read message prefix on control stream (CioStream socket to <*>:<*>`
- 2行：`rts panic! - stopping execution`
- 2行：`Lustre mount FAILED : bglio<*> : block_id : location`

## 7. 结论

本次任务证明项目可以稳定读取真实结构化CSV、完成字段映射、事件聚合和报告生成，但当前九类关键词规则不能泛化为通用日志异常检测器。其主要价值仍是对已覆盖通用故障表达生成证据链，而不是发现BGL领域中的未知内核异常。

日志级别参考基线在BGL上也会产生明显误报，说明仅依赖FATAL/ERROR同样不足。下一步应增加“未知严重事件”通道、模板频次异常检测和领域适配规则，并用独立数据复测，而不是把BGL标签直接硬编码进现有规则。

## 8. 限制

- BGL是超算领域日志，当前规则面向通用服务器、网络、数据库和应用故障，属于明显的领域外评测。
- BGL标签表示alert/non-alert，不等同于本项目的根因类别标签。
- severity-only仅作为参考基线，不是项目新增算法。

## 9. 来源

- Loghub数据仓库：https://github.com/logpai/loghub
- BGL样本与标签说明：https://github.com/logpai/loghub/tree/master/BGL
- Jieming Zhu等，《Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics》，ISSRE 2023。
