# 阻断事件管理框架 — 验证策略与测试用例

> 验证目标：覆盖 §10 步骤流程、§12 可靠性设计、§9 错误码、HA 打点、阻断事件产生源原则
> 测试方式：C++ 单元测试（gtest/gmock，`auth_coordinator_test.cpp` 扩展）+ JS 接口 Demo（`@ohos.security.securityGuard`）

## 一、验证策略总览

### 1.1 测试分层

| 层级 | 范围 | 位置 | 目的 |
|---|---|---|---|
| L1 单元测试 | AuthCoordinator / SubscribeManager / SessionService | `test/unittest/data_collect/sa/auth_coordinator_test.cpp` | 验证聚合算法、计数、超时、错误码 |
| L2 集成测试 | kit SDK ↔ SA（mock IPC） | `test/unittest/data_collect/sa/` | 验证 promise 同步转异步、退避重连、配额 |
| L3 接口验证 | JS NAPI 端到端 | `test/unittest/napi/auth_framework_demo.ets` | 验证 createAuthProvider / requestAuthResult 真实链路 |

### 1.2 错误码验证矩阵

| 错误码 | 常量 | 触发条件 | 测试方法 |
|---|---|---|---|
| 201 | NO_PERMISSION | HAP 无 `ohos.permission.AUTH_SERVICE_ACCESS` | mock VerifyAccessToken 返回 DENIED |
| 202 | NO_SYSTEMCALL | HAP 非系统应用 | mock IsSystemAppByFullTokenID 返回 false |
| 27000001 | AUTH_PROVIDER_INTERNAL_ERROR | provider null / invalid / IPC 失败 | 传 null provider / MarkInvalid 后调用 |
| 27000002 | AUTH_PROVIDER_EXCEED_PROCESS_LIMIT | 同 pid 第二个 provider | 同 pid 调两次 CreateAuthProvider |
| 27000003 | AUTH_PROVIDER_EXCEED_GLOBAL_LIMIT | 设备第 17 个 provider | 循环创建 16 个 + 第 17 个 |
| 27000004 | AUTH_REQUEST_EXCEED_LIMIT | 单 provider 第 129 个并发请求 | 循环调 128 次 RequestAuthResult 不让完成 |

## 二、C++ 单元测试用例（auth_coordinator_test.cpp 扩展）

每个用例标注：验收点、前置条件、操作、断言。

### TC01 — 从严策略：任一 DENY 立即阻断（验收 #13）
- **验收点**：13
- **前置**：1 个 Provider + 2 个订阅 Client-1/Client-2（strategy=ALLOW）
- **操作**：Provider RequestAuthResult → Client-1 SetAuthResult(DENY)
- **断言**：结果回调 `mergedAuthStrategy == DENY`，`clientResults[client-1] == DENY`
- **预期耗时**：< 400ms（DENY 立即触发，不等 Client-2）

### TC02 — 从严策略：全部 ALLOW 才放行（验收 #14）
- **验收点**：14
- **前置**：1 Provider + 2 Client（strategy=ALLOW）
- **操作**：RequestAuthResult → Client-1 ALLOW → Client-2 ALLOW
- **断言**：`mergedAuthStrategy == ALLOW`，`sentClientCount` 归零，`defaultDenyCount` 归零

### TC03 — 超时 DENY 触发阻断（验收 #15）
- **验收点**：15
- **前置**：1 Provider + 1 Client（defaultTimeoutStrategy=DENY）
- **操作**：RequestAuthResult → 不回填，等 400ms
- **断言**：`mergedAuthStrategy == DENY`，`clientResults[clientId] == DENY`

### TC04 — 超时 ALLOW 不阻断（验收 #16）
- **验收点**：16
- **前置**：1 Provider + 1 Client（defaultTimeoutStrategy=ALLOW）
- **操作**：RequestAuthResult → 不回填，等 400ms
- **断言**：`mergedAuthStrategy == ALLOW`，`clientResults[clientId] == TIMEOUT`

### TC05 — 无订阅 Client 默认放行（验收 #18）
- **验收点**：18
- **前置**：1 Provider，0 Client
- **操作**：RequestAuthResult
- **断言**：`mergedAuthStrategy == ALLOW`，`clientAuthResult` 为空

### TC06 — 降级 Client 只通知不参与聚合（验收 #17）
- **验收点**：17
- **前置**：1 Provider + 2 Client，AuthEventInfo.clientStatus 标 Client-1 为 degraded
- **操作**：RequestAuthResult → Client-2 ALLOW
- **断言**：`mergedAuthStrategy == ALLOW`，`clientResults` 仅含 Client-2（Client-1 不在结果中）

### TC07 — per-client seqnum 独有递增（验收 #9）
- **验收点**：9
- **前置**：1 Provider + 1 Client
- **操作**：RequestAuthResult 连续 3 次
- **断言**：Client 收到 3 次 OnAuthEvent，seqnum 分别为 1、2、3，metadata 含 `"seqNum":N`

### TC08 — 组合 key 路由正确（验收 #11）
- **验收点**：11
- **前置**：1 Provider + 2 Client（clientId 不同，seqnum 各自从 1 开始）
- **操作**：RequestAuthResult → Client-1 SetAuthResult(seqnum=1, DENY)
- **断言**：正确路由到 Client-1 的 RoutingContext，不影响 Client-2

### TC09 — 聚合完成后清理所有映射（验收 #19）
- **验收点**：19
- **前置**：1 Provider + 1 Client
- **操作**：RequestAuthResult → SetAuthResult(ALLOW)
- **断言**：`routingContexts_` 为空，`seqnumToRequestId_` 为空，`seqnumToSession_` 为空

### TC10 — 并发请求超限返回 27000004（错误码）
- **前置**：1 Provider
- **操作**：循环调 128 次 RequestAuthResult（不让完成），第 129 次
- **断言**：第 129 次返回 `AUTH_REQUEST_EXCEED_LIMIT(27000004)`

### TC11 — Provider 进程超限返回 27000002（错误码）
- **前置**：pid=2000 已创建 1 个 Provider
- **操作**：pid=2000 再创建第 2 个
- **断言**：返回 `AUTH_PROVIDER_EXCEED_PROCESS_LIMIT(27000002)`

### TC12 — Provider 全局超限返回 27000003（错误码）
- **前置**：循环创建 16 个 Provider（不同 pid）
- **操作**：第 17 个
- **断言**：返回 `AUTH_PROVIDER_EXCEED_GLOBAL_LIMIT(27000003)`

### TC13 — Destroy 幂等（验收 #22）
- **前置**：1 Provider
- **操作**：DestroyAuthProvider → 再 DestroyAuthProvider
- **断言**：两次都正常返回，无 crash

### TC14 — IPC 立即返回，dispatch 在 ffrt 异步（步骤 3+4）
- **前置**：1 Provider + 2 Client（模拟 OnAuthEvent 阻塞 200ms）
- **操作**：RequestAuthResult
- **断言**：RequestAuthResult 在 < 10ms 内返回 SUCCESS（不等 dispatch 完成）

### TC15 — DENY 打点包含应用信息+事件信息+发送时间（HA 打点）
- **前置**：mock `AuthEventReporter::ReportAuthBlockResult`
- **操作**：RequestAuthResult → SetAuthResult(DENY)
- **断言**：mock 被调用，参数含 pid/uid/eventId/content/metadata，sendTimeMs > 0

### TC16 — 超时打点包含应用信息+事件信息+超时时间（HA 打点）
- **前置**：mock `AuthEventReporter::ReportTimeoutResult`，1 Client(strategy=DENY)
- **操作**：RequestAuthResult → 不回填，等 400ms
- **断言**：mock 被调用，参数含 pid/uid/eventId/content/metadata/timeoutMs=400

### TC17 — Provider 无效时 ffrt 任务兜底返回 ALLOW（可靠性）
- **前置**：1 Provider + 1 Client
- **操作**：RequestAuthResult 后立即 DestroyAuthProvider（MarkInvalid），等 ffrt 完成
- **断言**：结果回调 `mergedAuthStrategy == ALLOW`，activeRequestCount 归零

### TC18 — 订阅者销毁异步通知 Provider 状态变更（可靠性一.1）
- **前置**：1 Provider + 1 Client，mock Provider 的 OnClientStatusChanged
- **操作**：DestroyAuthEventClient
- **断言**：Provider 收到 OnClientStatusChanged，clientInfos 不含已销毁的 Client

### TC19 — kit promise/future 同步等待超时返回 TIMEOUT（可靠性四）
- **前置**：kit 层 RequestAuthResult，SA 不回调
- **操作**：调 kit RequestAuthResult
- **断言**：400ms 后 callback 收到 `mergedAuthStrategy == TIMEOUT`

## 三、验证执行方式

```bash
# C++ 单元测试编译与执行（在 OpenHarmony 源码树）
cd /home/ubuntu/oh/master
./build.sh --product-name {pc_product} --build-target SecurityGuardDataCollectSaTest
# 执行测试
hdc shell aa test -b SecurityGuardDataCollectSaTest -m /data/test/
```

## 四、JS 接口 Demo（端到端验证）

见同目录 `auth_framework_demo.ets`。
