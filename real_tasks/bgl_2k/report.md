# BGL 2K 开放集日志初筛任务报告

## 1. 企业任务定义

将2,000行批量日志压缩为可解释的人工复核队列：已知故障继续分类，未命中规则的严重日志进入“未知严重事件”，再按级别、模板重复和跨对象传播进行优先级排序。系统全程只读，不执行修复。

## 2. 数据

- 来源：[https://github.com/logpai/loghub/blob/master/BGL/BGL_2k.log_structured.csv](https://github.com/logpai/loghub/blob/master/BGL/BGL_2k.log_structured.csv)
- 样本：2000行，其中告警143行、非告警1857行
- SHA-256：`3fe74103c0b02a28514534e2a47257a3f770135ca61afd425bbd3b9d6a31fe26`
- 第一列为`-`时表示非告警，其他标签表示告警。

## 3. 消融实验

| 版本 | Precision | Recall | F1 | FPR | MCC | TP / FP / FN / TN |
|---|---:|---:|---:|---:|---:|---:|
| V1 仅已知规则 | 0.182 | 0.042 | 0.068 | 0.015 | 0.055 | 6 / 27 / 137 / 1830 |
| V2 +未知严重事件 | 0.367 | 1.000 | 0.537 | 0.133 | 0.564 | 143 / 247 / 0 / 1610 |
| V3 +模板中高优先级 | 0.415 | 0.874 | 0.563 | 0.095 | 0.562 | 125 / 176 / 18 / 1681 |
| V4 仅高优先级 | 0.391 | 0.252 | 0.306 | 0.030 | 0.273 | 36 / 56 / 107 / 1801 |
| 严重级别参考基线 | 0.362 | 1.000 | 0.532 | 0.136 | 0.559 | 143 / 252 / 0 / 1605 |

## 4. 人工复核工作量

- 原始日志：2000行，120个官方模板
- 项目复核队列：120个模板簇，其中高优先级19、中优先级24、低优先级77
- 行到复核项压缩率：94.0%
- 前10个复核项覆盖官方告警：25.2%

## 5. 性能

- 逐行平均：0.380 ms
- 逐行P95：0.751 ms
- 完整CSV：460.467 ms

## 6. 主要误报模板

- 35行：`idoproxydb hit ASSERT condition: ASSERT expression=0 Source file=idotransportmgr.cpp Source line=<*> Function=int IdoTransportMgr::SendPacket(IdoUdpMgr*, BglCtlPavTrace*)`
- 21行：`ciod: Error loading <*>: invalid or missing program image, No such file or directory`
- 20行：`instruction address: <*>`
- 19行：`ciod: Error loading /<*>: invalid or missing program image, Permission denied`
- 18行：`ciod: LOGIN chdir(<*>) failed: No such file or directory`
- 17行：`ciod: Error loading /<*>: invalid or missing program image, Exec format error`
- 8行：`data address: <*>`
- 7行：`core configuration register: <*>`
- 7行：`MACHINE CHECK DCR read timeout (mc=<*> iar <*> lr <*>)`
- 5行：`machine check: i-fetch......................<*>`

## 7. 结论

未知严重事件通道解决了“未命中规则就完全漏掉”的问题；模板聚合把逐行告警转化为有限的复核项，并保留评分原因、对象、组件和样例证据。它现在能承担企业日志初筛与值班分流，但仍不能代替根因确认。

高召回带来的误报必须通过企业历史正常模板、组件知识、上下文窗口和阈值校准继续降低。不能把本次BGL结果宣传为企业生产准确率。

## 8. 限制

- BGL是超算领域日志，当前规则面向通用服务器、网络、数据库和应用故障，属于领域外评测。
- BGL标签表示alert/non-alert，不等同于本项目的根因类别标签。
- 模板评分阈值为工程初始值，尚未在企业历史数据上校准。
- 复核队列只做只读分流，不自动执行修复。

## 9. 来源

- Loghub：https://github.com/logpai/loghub
- BGL说明：https://github.com/logpai/loghub/tree/master/BGL
- Jieming Zhu等，《Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics》，ISSRE 2023。
