# 日志覆盖分析报告

> 分析日期：2026-10-17
> 范围：阻断服务提供者框架新增代码

## 一、日志级别原则

| 级别 | 使用场景 | 示例 |
|---|---|---|
| **SGLOGI** (INFO) | 低频路径：会话级、请求级入口/出口、关键状态变更 | CreateAuthProvider 入口、RequestAuthResult 入口、ffrt 任务启停、聚合完成 |
| **SGLOGD** (DEBUG) | 高频路径：per-client per-request 的循环内操作 | SetAuthResult 分片查找命中、DecrementCounters 计数变更、OnAuthEvent 逐个推送 |
| **SGLOGW** (WARN) | 非预期但可恢复：超时、降级触发 | 400ms 超时、provider 死亡 |
| **SGLOGE** (ERROR) | 错误：参数非法、查找失败、proxy null | seqnumKey not found、callback proxy null |

## 二、日志覆盖统计

### 修改前后对比

| 文件 | 修改前 | 修改后 | 新增 |
|---|---|---|---|
| auth_coordinator.cpp | 48 | 67 | +19 |
| auth_provider_session_service.cpp | 7 | 7 | 0（已充足） |
| auth_event_subscribe_manager.cpp | 22 | 22 | 0（已充足） |
| auth_event_reporter.cpp | 2 | 2 | 0（已充足） |
| auth_provider_subscribe_client.cpp (kit) | 24 | 27 | +3 |
| napi_block_framework.cpp | 10 | 15 | +5 |
| **合计** | **113** | **140** | **+27** |

### auth_coordinator.cpp 按级别分布

| 级别 | 数量 | 用途 |
|---|---|---|
| SGLOGI | 27 | 低频入口/出口/状态变更 |
| SGLOGD | 15 | 高频 per-client 调试日志 |
| SGLOGW | 4 | 超时/降级告警 |
| SGLOGE | 21 | 错误路径 |

## 三、关键路径日志覆盖

### 3.1 CreateAuthProvider（会话级，低频）

| 节点 | 日志 | 级别 |
|---|---|---|
| 入口 | `CreateAuthProvider, serviceId, pid` | INFO ✅ |
| 配额超限 | `provider exceed global/process limit` | ERROR ✅ |
| callback 重复 | `callback already has provider` | ERROR ✅ |
| death recipient 失败 | `add death recipient fail` | ERROR ✅ |
| 成功 | `create auth provider success` | INFO ✅ |
| 状态通知 | `collect client infos, count` + `notify client status changed, clientCount, providerCount` | INFO ✅ |

### 3.2 RequestAuthResult（请求级，低频）

| 节点 | 日志 | 级别 |
|---|---|---|
| 入口 | `RequestAuthResult, eventId, requestId, activeRequestCount` | INFO ✅ |
| 并发超限 | `per-provider request exceed limit` | ERROR ✅ |
| provider 不在集合 | `provider not found in sessions` | ERROR ✅ |
| 受理 | `request accepted, eventId` | INFO ✅ |
| ffrt 提交 | `submit ffrt task, requestId, eventId` | INFO ✅ |
| ffrt 启动 | `ffrt task start, requestId` | INFO ✅ |
| provider 失效 | `provider invalid in ffrt task` | ERROR ✅ |
| 无订阅 Client | `no subscribed client, default ALLOW` | INFO ✅ |
| 注册完成 | `routing context registered, requestId, sentClientCount` | INFO ✅ |
| 等待开始 | `wait for completion, requestId, eventId, pendingCount` | INFO ✅ |
| 聚合完成 | `eventId completed, mergedStrategy` | INFO ✅ |
| 任务完成 | `async done, requestId, mergedStrategy` | INFO ✅ |

### 3.3 Dispatch（请求级，低频 + per-client 高频）

| 节点 | 日志 | 级别 |
|---|---|---|
| 订阅查询 | `eventId, requestId, subscribed count` | INFO ✅ |
| per-client dispatch | `dispatch, eventId, seqnum, clientId` | DEBUG ✅ |
| dispatch 完成 | `dispatch done, sentClientCount, defaultDenyCount` | INFO ✅ |
| 推送开始 | `push events to clients, eventId, count` | INFO ✅ |
| per-client 推送 | `OnAuthEvent pushed, eventId, seqnum` | DEBUG ✅ |
| 推送完成 | `push events done, eventId` | DEBUG ✅ |
| proxy null | `callback proxy is null, seqnum` | ERROR ✅ |

### 3.4 降级客户端（低频）

| 节点 | 日志 | 级别 |
|---|---|---|
| 入口 | `notify degraded client, eventId, seqnum` | INFO ✅ |
| proxy null | `degraded client callback proxy is null` | ERROR ✅ |
| 完成 | `degraded client notified, seqnum` | DEBUG ✅ |

### 3.5 SetAuthResult（per-client per-request，高频）

| 节点 | 日志 | 级别 |
|---|---|---|
| 入口 | `SetAuthResult, seqnum, authStrategy` | DEBUG ✅ |
| 分片未命中 | `seqnumKey not found` | ERROR ✅ |
| 分片命中 | `seqnumKey hit, clientId, seqnum, shardIdx` | DEBUG ✅ |
| 已完成跳过 | `ctx already completed, skip` | DEBUG ✅ |
| 计数递减 | `decrement counters, clientId, sentClientCount, defaultDenyCount` | DEBUG ✅ |
| 完成 | `SetAuthResult done, clientId, strategy, sentClientCount` | DEBUG ✅ |
| DENY 策略触发 | `strict policy: DENY, eventId` | INFO ✅ |
| 全部 ALLOW | `strict policy: all ALLOW, eventId` | INFO ✅ |

### 3.6 超时处置（per-client 遍历）

| 节点 | 日志 | 级别 |
|---|---|---|
| 超时触发 | `eventId timeout, handling pending clients` | WARN ✅ |
| DENY 超时 | `timeout DENY triggers block, clientId` | WARN ✅ |
| ALLOW 超时 | `timeout ALLOW client, record TIMEOUT, clientId` | DEBUG ✅ |
| per-client 超时 | `timeout, clientId, strategy` | DEBUG ✅ |
| 全部 ALLOW 超时 | `all timeout clients ALLOW, mergedAuthStrategy=ALLOW` | INFO ✅ |

### 3.7 清理与状态通知

| 节点 | 日志 | 级别 |
|---|---|---|
| 清理完成 | `routing context cleaned, requestId` | DEBUG ✅ |
| 收集 Client | `collect client infos, count` | INFO ✅ |
| 通知开始 | `notify client status changed, clientCount, providerCount` | INFO ✅ |
| 通知完成 | `notify clients status changed done, providerCount` | DEBUG ✅ |
| proxy null | `auth provider callback proxy is null` | ERROR ✅ |

### 3.8 kit 层 RequestAuthResult

| 节点 | 日志 | 级别 |
|---|---|---|
| 入口 | `RequestAuthResult` | INFO ✅ |
| SA 拒绝 | `SA RequestAuthResult rejected, ret, eventId` | ERROR ✅ |
| SA 受理 | `SA RequestAuthResult accepted, eventId, waiting` | INFO ✅ |
| kit 超时 | `kit wait auth result timeout, return TIMEOUT` | WARN ✅ |
| 收到回调 | `kit got auth result, mergedStrategy, eventId` | INFO ✅ |

### 3.9 NAPI 层 RequestAuthResult

| 节点 | 日志 | 级别 |
|---|---|---|
| Execute 入口 | `RequestAuthResultExecute start, eventId` | INFO ✅ |
| 回调到达 | `RequestAuthResult callback received, mergedStrategy` | INFO ✅ |
| SA 拒绝 | `RequestAuthResult rejected, ret` | ERROR ✅ |
| Complete resolve | `RequestAuthResultComplete resolve, mergedStrategy` | INFO ✅ |
| Complete reject | `RequestAuthResultComplete reject, ret` | ERROR ✅ |

## 四、新增日志清单（27 条）

### auth_coordinator.cpp（+19 条）

| # | 函数 | 日志内容 | 级别 | 频率 |
|---|---|---|---|---|
| 1 | NotifyDegradedClient | `notify degraded client, eventId, seqnum` | INFO | 低频 |
| 2 | NotifyDegradedClient | `degraded client callback proxy is null` | ERROR | 异常 |
| 3 | NotifyDegradedClient | `degraded client notified, seqnum` | DEBUG | 低频 |
| 4 | PushEventsToClients | `push events to clients, eventId, count` | INFO | per-request |
| 5 | PushEventsToClients | `OnAuthEvent pushed, eventId, seqnum` | DEBUG | per-client |
| 6 | PushEventsToClients | `push events done, eventId` | DEBUG | per-request |
| 7 | RegisterRoutingContext | `register routing context, requestId, eventId, sentClientCount` | INFO | per-request |
| 8 | ProcessAuthResultAsync | `submit ffrt task, requestId, eventId` | INFO | per-request |
| 9 | ProcessAuthResultAsync | `ffrt task start, requestId` | INFO | per-request |
| 10 | ProcessAuthResultAsync | `routing context created, requestId, contentLen` | DEBUG | per-request |
| 11 | ProcessAuthResultAsync | `routing context registered, requestId, sentClientCount` | INFO | per-request |
| 12 | WaitForCompletion | `wait for completion, requestId, eventId, pendingCount` | INFO | per-request |
| 13 | RequestAuthResult | `activeRequestCount` 追加入口日志 | INFO | per-request |
| 14 | SetAuthResult | `seqnumKey hit, clientId, seqnum, shardIdx` | DEBUG | per-client |
| 15 | SetAuthResult | `ctx already completed, skip` | DEBUG | per-client |
| 16 | SetAuthResult | `SetAuthResult done, clientId, strategy, sentClientCount` | DEBUG | per-client |
| 17 | DecrementCounters | `decrement counters, clientId, sentClientCount, defaultDenyCount` | DEBUG | per-client |
| 18 | HandleTimeout | `timeout ALLOW client, record TIMEOUT, clientId` | DEBUG | per-client |
| 19 | CollectClientInfos / NotifyClientStatusChanged | `collect client infos, count` + `notify client status changed, clientCount, providerCount` | INFO | 低频 |

### auth_provider_subscribe_client.cpp kit 层（+3 条）

| # | 日志内容 | 级别 |
|---|---|---|
| 20 | `SA RequestAuthResult rejected, ret, eventId` | ERROR |
| 21 | `SA RequestAuthResult accepted, eventId, waiting` | INFO |
| 22 | `kit got auth result, mergedStrategy, eventId` | INFO |

### napi_block_framework.cpp（+5 条）

| # | 日志内容 | 级别 |
|---|---|---|
| 23 | `RequestAuthResultExecute context or provider is null` | ERROR |
| 24 | `RequestAuthResultExecute start, eventId` | INFO |
| 25 | `RequestAuthResult callback received, mergedStrategy` | INFO |
| 26 | `RequestAuthResultComplete resolve, mergedStrategy` | INFO |
| 27 | `RequestAuthResultComplete reject, ret` | ERROR |

## 五、调试场景覆盖度

### 5.1 常见调试场景

| 调试场景 | 所需日志 | 覆盖 |
|---|---|---|
| Provider 创建失败 | 权限/配额/重复/death fail | ✅ |
| Provider 创建成功但未收到 Client 信息 | collect client infos + notify client status changed | ✅ |
| 请求被拒绝 | activeRequestCount + exceed limit | ✅ |
| 请求受理但无回调 | ffrt task start + wait for completion + async done | ✅ |
| 聚合结果不符合预期 | SetAuthResult hit/done + strict policy + build auth result | ✅ |
| 超时排查 | wait for completion + timeout handling + per-client timeout | ✅ |
| 分片查找失败 | seqnumKey not found | ✅ |
| 降级客户端未收到事件 | notify degraded client + proxy null | ✅ |
| 事件未推送到 Client | push events + OnAuthEvent pushed + proxy null | ✅ |
| kit 超时 | SA accepted + kit wait timeout | ✅ |
| NAPI Promise 未 resolve | Execute start + callback received + Complete resolve | ✅ |
| Provider 死亡后资源未清理 | provider died + destroy success | ✅ |

### 5.2 高并发调试场景

| 场景 | 关键日志 |
|---|---|
| 2560 并发请求 | `requestId` 贯穿全程，可按 requestId 过滤追踪单请求生命周期 |
| 多 Provider 同时创建 | `serviceId + pid` 区分不同 Provider |
| 分片锁竞争 | `shardIdx` 标识分片，可统计分片分布 |
| 超时雪崩 | `timeout handling` + `pendingCount` 判断等待队列深度 |
| 内存泄漏 | `activeRequestCount` 追踪是否正确递减 |
