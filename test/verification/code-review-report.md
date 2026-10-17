# 阻断服务提供者框架 — 全面代码审查报告

> 审查范围：PR #514（已合并）+ 本次可靠性修改（M1–M14）
> 审查维度：inner_api/JS 一致性、设计/实现一致性、架构合理性、并发安全、资源释放
> 重点场景：20+ Provider × 128 并发请求 = 2560+ 并发 RoutingContext

## 一、总览

| 类别 | 严重度 | 数量 | 说明 |
|---|---|---|---|
| 🔴 致命 | P0 | 3 | UAF、数据竞争、会导致 crash |
| 🟠 高危 | P1 | 3 | 内存泄漏、线程池耗尽、锁竞争 |
| 🟡 中危 | P2 | 3 | 接口不一致、死代码、性能瓶颈 |
| 🟢 低危 | P3 | 2 | 风格/可维护性 |

---

## 二、🔴 致命问题（P0，必须修复）

### P0-1：SetAuthResult 与 WaitForCompletion 之间的 Use-After-Free

**位置**：`auth_coordinator.cpp:SetAuthResult` (行 521–556) vs `WaitForCompletion` (行 357–378)

**问题**：`SetAuthResult` 在 `mutex_` 锁内获取 `ctx` 引用后**释放 `mutex_`**，再锁定 `ctx.ctxMutex`。但 `WaitForCompletion` 在超时后会在 `mutex_` 锁内 `routingContexts_.erase(requestId)`，此时 `unique_ptr` 析构 → `ctx` 被销毁 → `ctx.ctxMutex` 被销毁 → `SetAuthResult` 的 `cvLock(ctx.ctxMutex)` 操作已销毁的 mutex。

```
时序：
  IPC 线程 (SetAuthResult)           ffrt 线程 (WaitForCompletion)
  ───────────────────────             ─────────────────────────────
  lock(mutex_)
  find ctx → 得到引用
  unlock(mutex_)                      future.wait_for(400ms) → timeout
                                      HandleTimeout(ctx)
  ─── 缝隙 ───                        lock(mutex_)
  lock(ctx.ctxMutex)  ← UAF!          routingContexts_.erase(requestId)
                                      → unique_ptr 析构 → ctx 析构
                                      → ctxMutex 已销毁
                                      unlock(mutex_)
```

**后果**：crash（操作已销毁的 mutex），或数据损坏。

**修复方案**：`SetAuthResult` 全程持 `mutex_`，不在 `mutex_` 与 `ctxMutex` 之间留缝隙。或改用 `shared_ptr<RoutingContext>` 延长生命周期：

```cpp
// 方案A（推荐）：SetAuthResult 全程持 mutex_，不单独锁 ctxMutex
int32_t AuthCoordinator::SetAuthResult(..., int32_t authStrategy)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);  // 全程持有
    // ... 查找 ctx ...
    auto &ctx = *(ctxIter->second);
    if (ctx.completed) { return SUCCESS; }
    // ... 修改 ctx 字段（不再单独锁 ctxMutex）...
    DecrementCounters(ctx, clientId);
    EvaluateStrictPolicy(ctx, strategy, ctx.eventId);
    return SUCCESS;
}
// 同时 WaitForCompletion 的 erase 也在 mutex_ 锁内，保证不会在 SetAuthResult 执行期间 erase
```

> 注：方案A 需移除 `ctxMutex`，所有 ctx 字段访问统一在 `mutex_` 保护下。`HandleTimeout` 也需在 `mutex_` 保护下执行（见 P0-2）。

---

### P0-2：HandleTimeout 数据竞争 — 未加锁访问 ctx 共享字段

**位置**：`auth_coordinator.cpp:HandleTimeout` (行 319–355)

**问题**：`HandleTimeout` 在 ffrt 线程中**无任何锁**读写 `ctx.clientResults`、`ctx.clientPromises`、`ctx.completed`、`ctx.mergedAuthStrategy`，而 `SetAuthResult` 在 IPC 线程持 `ctxMutex` 读写同一批字段。

```
ffrt 线程 (HandleTimeout)              IPC 线程 (SetAuthResult)
─────────────────────────              ─────────────────────────
（无锁）                                lock(ctxMutex)
ctx.clientResults[cid] = DENY          ctx.clientResults[cid] = ALLOW  ← 数据竞争
ctx.completed = true                   if (ctx.completed) ...          ← UB
```

**后果**：数据竞争（UB），可能导致聚合结果错误、`promise::set_value` 重复调用抛异常。

**修复方案**：与 P0-1 统一，`HandleTimeout` 在 `mutex_` 保护下执行（方案A），或独立加 `ctxMutex`（但需解决 P0-1 的 UAF）。

---

### P0-3：ProcessAuthResultAsync ffrt 任务中 Provider 裸指针 UAF

**位置**：`auth_coordinator.cpp:ProcessAuthResultAsync` (行 399–457)

**问题**：ffrt lambda 捕获 `provider` 为裸指针 `AuthProviderSessionService *`。`DestroyAuthProvider`/`RemoveProvider` 会 `MarkInvalid()` + 从 `providerSessions_` 移除。但移除后 sptr 引用计数可能归零 → provider 析构 → ffrt 任务中 `provider->DecrementActiveRequest()` UAF。

```
ffrt 线程                              IPC 线程 (DestroyAuthProvider)
──────────────                         ──────────────────────────────
provider->IsValid() == true            MarkInvalid()
... dispatch ...                       RemoveProviderLocked()
                                      → sptr 析构 → provider 析构
provider->DecrementActiveRequest()     ← UAF!
```

`IsValid()` 检查存在 TOCTOU 竞争：检查通过后 provider 仍可能被销毁。

**修复方案**：ffrt lambda 捕获 `sptr<AuthProviderSessionService>` 而非裸指针，确保生命周期：

```cpp
void AuthCoordinator::ProcessAuthResultAsync(sptr<AuthProviderSessionService> provider,
    int64_t requestId, const AuthEventInfo &event, const sptr<IRemoteObject> &resultCallback)
{
    ffrt::submit([this, provider, requestId, event, resultCallback]() {
        // provider 是 sptr，生命周期由 ffrt 任务保证
        if (provider == nullptr || !provider->IsValid()) {
            // ... fallback ...
            return;
        }
        // ... dispatch + wait + notify ...
        provider->DecrementActiveRequest();  // 安全
    });
}
```

`RequestAuthResult` 中传 `provider` 的 sptr（从 `providerSessions_` 集合获取，需在 `mutex_` 锁内拷贝 sptr）。

---

## 三、🟠 高危问题（P1）

### P1-1：Provider 与 DeathRecipient 循环引用导致内存泄漏

**位置**：`auth_provider_session_service.h`

```
AuthProviderSessionService                     AuthProviderSessionDeathRecipient
├─ deathRecipient_ (sptr<...DeathRecipient>)  ├─ provider_ (sptr<...SessionService>)
└─ ...                                         └─ ...
         ↑                                          ↑
         └────────── 循环引用 ──────────────────────┘
```

`DestroyAuthProvider` 调 `RemoveDeathRecipient`（从 callback 移除）但**未清空 `provider->deathRecipient_`**，`RemoveProvider`（死亡回调路径）**完全未处理 DeathRecipient**。循环引用导致两者都无法析构。

**后果**：每个 Provider 销毁后泄漏 `AuthProviderSessionService` + `DeathRecipient` 对象。20+ Provider 反复创建/销毁会持续泄漏。

**修复方案**：销毁路径显式断开循环引用：

```cpp
void AuthCoordinator::DestroyAuthProvider(AuthProviderSessionService *provider)
{
    // ... 现有逻辑 ...
    // 断开循环引用
    keepAlive->SetDeathRecipient(nullptr);  // 新增：清空 provider 持有的 deathRecipient_
    // keepAlive 析构时 deathRecipient_ 已空 → deathRecipient 析构 → provider_ sptr 释放 → provider 析构
}

void AuthCoordinator::RemoveProvider(const sptr<AuthProviderSessionService> &provider)
{
    // ... 现有逻辑 ...
    provider->SetDeathRecipient(nullptr);  // 新增
}
```

---

### P1-2：20+ Provider × 128 请求 = 2560+ ffrt 任务阻塞，线程池耗尽风险

**位置**：`ProcessAuthResultAsync` 的 `ffrt::submit` + `WaitForCompletion` 的 `future.wait_for(400ms)`

**问题**：每个请求创建一个 ffrt 任务，每个任务阻塞最多 400ms。ffrt 线程池默认线程数有限（通常 = CPU 核数）。2560 个任务中，前 N 个占满线程池后全部阻塞在 `wait_for`，剩余 2560−N 个任务排队无法执行 dispatch → Client 收不到事件 → 无法回填 → 已运行的任务全部超时 → 雪崩。

```
CPU 8 核 → ffrt 线程池 ~8 线程
8 个任务占满线程池，全部 wait_for(400ms)
剩余 2552 个任务排队
→ 2552 个 Client 迟迟收不到事件
→ 8 个任务超时返回 TIMEOUT
→ 新 8 个任务开始，但 Client 可能已超时
→ 雪崩：大部分请求超时
```

**后果**：高并发下大量请求超时返回 TIMEOUT，阻断框架实际失效。

**修复方案**：

1. **分离 dispatch 与 wait**：dispatch 不阻塞，wait 单独在独立线程池
2. **限制 ffrt 并发**：用信号量限制同时 wait 的任务数
3. **改用定时器替代阻塞 wait**：用 `ffrt::timer` 或 `std::async` + 超时回调，不占线程

```cpp
// 方案C（推荐）：dispatch 后注册定时器，不阻塞
void AuthCoordinator::ProcessAuthResultAsync(...)
{
    ffrt::submit([...]() {
        // dispatch（快速，不阻塞）
        DispatchEventToClients(params);
        RegisterRoutingContext(requestId, ctx);
        // 注册 400ms 定时器（不占线程）
        ffrt::timer_queue::submit(400ms, [this, requestId, ...]() {
            HandleTimeoutIfNotCompleted(requestId);
        });
    });
}
// Client 回填或定时器触发后，通过 requestId 查找 ctx 并处理
```

---

### P1-3：全局 mutex_ 锁竞争瓶颈

**位置**：`auth_coordinator.h:mutex_`

**问题**：所有 Provider 的所有请求共享一个 `mutex_`，保护 `routingContexts_`、`seqnumToRequestId_`、`seqnumToSession_`、`providerSessions_`。2560+ 并发请求的 `SetAuthResult`（每 Client 回填一次）都竞争同一把锁。

**后果**：高并发下 `mutex_` 成为瓶颈，IPC 线程等待锁时间增加，可能导致 Client 回填超时。

**修复方案**：按 requestId 分片锁，或用 `concurrent_map`：

```cpp
// 方案：按 requestId 分桶
static constexpr size_t LOCK_SHARD_COUNT = 16;
ffrt::mutex shards_[LOCK_SHARD_COUNT];
ffrt::mutex& GetShard(int64_t requestId) {
    return shards_[requestId % LOCK_SHARD_COUNT];
}
// routingContexts_ 按 shard 分桶存储
```

---

## 四、🟡 中危问题（P2）

### P2-1：seqnumToSession_ 存储裸指针但从未读取 — 死代码 + 悬垂指针风险

**位置**：`auth_coordinator.h:139`

```cpp
std::map<std::string, AuthEventSessionService *> seqnumToSession_{};
```

全仓搜索：`seqnumToSession_` 只在 `RegisterNormalClient` 写入、`WaitForCompletion` erase，**从未被读取**。存储的裸指针在 Client 进程死亡后变为悬垂指针。虽未被解引用不会 crash，但属死代码且误导维护者。

**修复**：删除 `seqnumToSession_`（若设计上不需要反查 session）。

---

### P2-2：d.ts 与 C++ 实现的接口不一致

| 接口项 | d.ts 定义 | C++ 实现 | 差异 |
|---|---|---|---|
| `createAuthProvider` 返回值 | `AuthProvider`（同步） | NAPI 同步返回对象 ✅ | 一致 |
| `requestAuthResult` 返回值 | `Promise<AuthResult>` | NAPI `napi_async_work` + kit `promise/future` ✅ | 一致（修改后） |
| `destroyAuthProvider` 返回值 | `void` | NAPI 返回 null ✅ | 一致 |
| Provider 全局上限 | `16` | `MAX_AUTH_PROVIDER_SIZE = 16` ✅ | 一致 |
| 并发请求上限 | d.ts 未说明 | `128/Provider` | ⚠️ d.ts 缺少并发上限说明 |
| `27000004` 描述 | `Concurrent request count has reached the upper limit` | C++ `单 Provider 并发请求超限` | ⚠️ 描述范围不一致（d.ts 未说明 per-provider） |
| `AuthClientStatus.isDegraded` | 必填（无 `?`） | NAPI 已改必填 ✅ | 一致（修改后） |
| `AuthClientInfo.bundleName` | 必填 `string` | C++ 置空 `""` | ❌ Provider 收到空字符串，d.ts 未标注可能为空 |
| `AuthStrategy.TIMEOUT` | 枚举值 `2` | C++ `TIMEOUT = 2` ✅ | 一致 |
| `onClientStatusChanged` 入参 | `AuthClientInfo[]` | `CollectClientInfos` 填充 ✅ | 一致（修改后） |

**需修复**：
1. d.ts 补充并发上限 `128` 的说明（在 `requestAuthResult` 的 `@throws 27000004` 注释中）
2. d.ts 的 `AuthClientInfo.bundleName` 标注 `@since` 可能为空，或 C++ 实际填充

---

### P2-3：NAPI 层 RequestAuthResultContext 生命周期 — kit 超时后回调仍可能触发

**位置**：`napi_block_framework.cpp:RequestAuthResultExecute` + kit `RequestAuthResult`

**问题**：kit `future.wait_for(400ms)` 超时后 callback(TIMEOUT) 返回，NAPI `RequestAuthResultComplete` 执行 `delete context`。但 SA 侧的 ffrt 任务可能仍在运行，SA 聚合完成后回调 `AuthResultCallbackService::OnAuthResult` → 调用已 delete 的 context 的 lambda → UAF。

```
NAPI worker 线程                    SA ffrt 线程
──────────────                      ───────────
kit future.wait_for(400ms) → timeout
callback(TIMEOUT)
RequestAuthResultComplete:
  resolve Promise(TIMEOUT)
  delete context                     SA 聚合完成
                                     → OnAuthResult(result)
                                     → context->result = result  ← UAF!
```

**修复方案**：kit 的 `callbackService` 使用 `weak_ptr<RequestAuthResultContext>` 或 `shared_ptr` 延长生命周期：

```cpp
// kit RequestAuthResult 中
auto weakCtx = std::weak_ptr<...>(contextPtr);  // 需改 context 为 shared_ptr
callbackService->RegistCallBack([weakCtx](const AuthResult &result) {
    auto ctx = weakCtx.lock();
    if (ctx != nullptr) {
        ctx->result = result;
    }
    // 若 ctx 已销毁（超时后），安全跳过
});
```

> 但当前 kit 的 promise/future 设计下，超时后 SA 回调写入已超时的 promise → `promise->set_value()` 抛 `promise_already_satisfied`（如果 promise 已被移除）。需在 callbackService 的 lambda 中 catch 异常或检查 promise 有效性。

---

## 五、🟢 低危问题（P3）

### P3-1：ProcessAuthResultAsync 中 event 按值捕获，大 content 场景拷贝开销

`AuthEventInfo` 按值捕获到 ffrt lambda，其中 `content` 字段可能达 4096 字节。2560 并发下拷贝开销不可忽视。建议改为 `shared_ptr<AuthEventInfo>` 或移动捕获。

### P3-2：EvaluateStrictPolicy 中 resultPromise->set_value 可能重复调用

若多个 Client 几乎同时回填，第一个 DENY 触发 `set_value(DENY)` + `completed=true`，第二个回填检查 `completed` 后返回。但 `completed` 检查与 `set_value` 之间如果不在同一锁内（P0-1 修复后统一在 `mutex_` 内则安全），可能重复 `set_value` 抛 `future_error`。

---

## 六、inner_api 与 JS 接口一致性总结

| 维度 | 一致性 | 说明 |
|---|---|---|
| 接口签名 | ✅ 基本一致 | createAuthProvider/destroyAuthProvider/requestAuthResult 签名匹配 |
| 错误码 | ⚠️ 部分不一致 | 27000004 描述范围不一致（d.ts 未说明 per-provider） |
| 枚举值 | ✅ 一致 | AuthStrategy ALLOW/DENY/TIMEOUT = 0/1/2 |
| 数据结构 | ✅ 一致 | AuthEventInfo/AuthResult/AuthClientInfo 字段匹配 |
| 必填校验 | ✅ 一致（修改后） | isDegraded 必填 |
| bundleName | ❌ 不一致 | C++ 置空，d.ts 未标注可能为空 |
| 并发上限 | ⚠️ 缺失 | d.ts 未说明 128 上限 |

---

## 七、设计 vs 实现一致性

| 设计要求 | 实现状态 | 偏差 |
|---|---|---|
| 步骤3: SA 同步 IPC 返回 | ✅ IPC 立即返回 SUCCESS（M11） | — |
| 步骤4: ffrt 异步 dispatch | ✅ dispatch 在 ffrt 任务中（M11） | — |
| 步骤7: ffrt 任务通过 seqnum 查找 | ⚠️ 在 IPC 线程同步查找 | 用户确认不需 ffrt |
| 步骤10: kit 同步返回策略 | ✅ kit promise/future.wait_for(400ms) | — |
| 从严策略 | ✅ 任一 DENY 立即阻断 | — |
| 超时策略 | ✅ 400ms + defaultTimeoutStrategy | — |
| HA 打点 | ✅ DENY + 超时打点（M13/M14） | — |
| Provider 退避重连 | ✅ {1,5,15,30,60...}（M5） | — |
| per-provider 128 并发 | ✅ activeRequestCount_ 原子计数（M6） | — |
| 客户端降级 | ✅ isDegraded=true 不参与聚合 | — |
| 阻断事件产生源原则 | ✅ Provider 只执行结果不做决策 | — |

---

## 八、修复优先级建议

### 第一优先（P0，阻断发布）

1. **P0-1 + P0-2 统一修复**：移除 `ctxMutex`，`SetAuthResult`、`HandleTimeout`、`EvaluateStrictPolicy` 全部在 `mutex_` 保护下执行。`WaitForCompletion` 的 `wait_for` 在 `mutex_` 锁外执行（不持锁等待），但 `erase` 在 `mutex_` 锁内。`SetAuthResult` 全程持 `mutex_` 避免与 `erase` 竞争。

2. **P0-3**：`ProcessAuthResultAsync` 改为捕获 `sptr<AuthProviderSessionService>`。

### 第二优先（P1，高并发场景必修）

3. **P1-1**：销毁路径断开循环引用（`SetDeathRecipient(nullptr)`）。
4. **P1-2**：分离 dispatch 与 wait，改用定时器替代阻塞 `wait_for`。
5. **P1-3**：按 requestId 分片锁，缓解全局锁竞争。

### 第三优先（P2，接口质量）

6. **P2-1**：删除 `seqnumToSession_` 死代码。
7. **P2-2**：d.ts 补充并发上限说明 + bundleName 可能为空标注。
8. **P2-3**：NAPI context 生命周期用 shared_ptr/weak_ptr 保护。

---

## 九、20+ Provider × 128 请求场景专项分析

### 9.1 资源消耗估算

| 资源 | 单请求 | 2560 并发 | 风险 |
|---|---|---|---|
| RoutingContext | ~200 字节 | ~500KB | 低 |
| ffrt 任务 | ~4KB 栈 | ~10MB | 中 |
| seqnumToRequestId_ 条目 | N Client × 1 | 2560 × N | 低 |
| promise/future | 2 个 | 5120 个 | 低 |
| 线程占用 | 1 个 ffrt 线程 | 2560 个 → 排队 | **高** |

### 9.2 并发问题矩阵

| 问题 | 触发条件 | 影响 | 修复 |
|---|---|---|---|
| ffrt 线程池耗尽 | 2560 任务 > 线程数 | 大量超时 | P1-2 定时器替代阻塞 |
| mutex_ 锁竞争 | 2560 SetAuthResult | 回填延迟 | P1-3 分片锁 |
| UAF on ctx | 超时与回填竞争 | crash | P0-1 统一锁 |
| Provider UAF | dispatch 中 Provider 销毁 | crash | P0-3 sptr 捕获 |
| 内存泄漏 | Provider 反复创建/销毁 | OOM | P1-1 断循环引用 |

### 9.3 推荐架构调整（针对高并发）

```
当前架构：
  IPC → RequestAuthResult → ffrt(dispatch + wait_for + notify)  ← 阻塞线程

推荐架构：
  IPC → RequestAuthResult → ffrt(dispatch only, 注册定时器)  ← 快速返回
                                    ↓
                        Client 回填 → SetAuthResult → 检查完成 → notify
                        定时器触发 → HandleTimeout → notify
```

将 `wait_for(400ms)` 阻塞改为定时器回调，dispatch ffrt 任务快速完成不占线程，等待由定时器和 Client 回填驱动，彻底解决线程池耗尽问题。
