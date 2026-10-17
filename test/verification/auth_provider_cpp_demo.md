# 阻断服务提供者（Provider）C++ 接口使用 Demo

> 本文档面向阻断服务提供者（Provider）的开发者，演示如何通过 C++ inner_api 接入阻断框架，
> 实现：阻断决策、放行决策、客户端降级操作。
>
> **核心原则**：Provider 只推送事件并请求结果，不做策略决策；框架内部按从严策略聚合，
> Provider 拿到 `AuthResult.mergedAuthStrategy` 后执行阻断或放行。

## 一、接口总览

```cpp
#include "auth_provider_subscribe_client.h"
#include "auth_event_info.h"
#include "auth_result.h"
#include "auth_strategy.h"
#include "auth_client_info.h"
#include "auth_client_status.h"

namespace OHOS::Security::SecurityGuard {
// 回调类型
using AuthProviderCallback = std::function<void(const std::vector<AuthClientInfo> &clientsInfo)>;
using AuthResultCallback   = std::function<void(const AuthResult &result)>;

// Provider SDK 主类
class AuthProviderSubscribeClient : public std::enable_shared_from_this<AuthProviderSubscribeClient> {
public:
    // 步骤1：创建 Provider 会话
    static int32_t CreateProvider(AuthProviderCallback callback, const std::string &serviceId,
        std::shared_ptr<AuthProviderSubscribeClient> &provider);
    // 步骤2：查询阻断策略
    int32_t RequestAuthResult(const AuthEventInfo &event, AuthResultCallback callback);
    // 步骤3：销毁
    void DeleteProvider();
};

// 事件信息
class AuthEventInfo {
public:
    AuthEventInfo(int64_t eventId, const std::string &version, const std::string &content);
    void SetClientStatus(const std::vector<AuthClientStatus> &status); // 降级客户端列表
};

// 阻断策略枚举
enum AuthStrategy { ALLOW = 0, DENY = 1, TIMEOUT = 2 };

// 阻断结果
class AuthResult {
public:
    AuthStrategy GetMergedAuthStrategy() const;                    // 最终聚合策略
    std::vector<ClientAuthResult> GetClientAuthResult() const;    // 每个客户端的明细
};

// 客户端状态（用于降级）
class AuthClientStatus {
public:
    AuthClientStatus(const std::string &clientId, bool isDegraded);
};
}
```

## 二、前置条件

| 项目 | 要求 |
|---|---|
| 权限 | `ohos.permission.AUTH_SERVICE_ACCESS` |
| 应用类型 | 系统应用（HAP）或 native SA（uid 白名单） |
| feature flag | `security_guard_auth_event_enable = true` |
| SA 状态 | SA 3524（data_collect）已运行 |
| 编译依赖 | `external_deps += ["security_guard:libsg_collect_sdk"]` |

## 三、完整使用步骤

### 步骤 1 — 创建 Provider 会话

创建 Provider 实例，注册 `onClientStatusChanged` 回调。创建成功后，框架会立即通过回调下发当前所有订阅客户端的全量列表。

### 步骤 2 — 查询阻断策略（核心）

当 Provider 发生阻断事件时，构造 `AuthEventInfo`，调用 `RequestAuthResult`：
- kit 内部用 `promise/future` **同步转异步**，阻塞当前业务线程最多 400ms
- 框架内部拉起 ffrt 异步任务：逐个 Client 推送事件 → Client 回填策略 → 从严聚合
- 聚合完成或超时后，经 `AuthResultCallback` 回调返回 `AuthResult`

### 步骤 3 — 根据结果执行阻断/放行

回调中拿到 `AuthResult`：
- `mergedAuthStrategy == DENY` → 执行阻断
- `mergedAuthStrategy == ALLOW` → 执行放行
- `mergedAuthStrategy == TIMEOUT` → kit 侧超时兜底，按业务策略处置

### 步骤 4 — 客户端降级操作（可选）

当 Provider 希望某个客户端「只收到事件通知，不参与阻断决策」时（如该客户端已无响应或仅需感知），在 `AuthEventInfo.clientStatus` 中标记 `isDegraded=true`。

### 步骤 5 — 销毁

Provider 退出时调用 `DeleteProvider()`，框架清理会话。

## 四、关键节点时序

```
Provider 业务线程:
  ┌─ RequestAuthResult(event) ──────────────────────────────┐
  │  kit: promise/future.wait_for(400ms) 同步阻塞            │
  │                                                          │
  │  SA ffrt 异步任务:                                        │
  │    1. 查询订阅 Client 列表                                 │
  │    2. 逐个 Client: 生成 per-client seqnum, 推送 OnAuthEvent│
  │    3. 等待 Client 回填 (future.wait_for(400ms))           │
  │    4. 从严聚合: 任一 DENY → 立即阻断; 全 ALLOW → 放行       │
  │    5. 超时: 按 Client defaultTimeoutStrategy 处置         │
  │    6. 回调 AuthResult → kit promise.set_value             │
  │                                                          │
  │  kit: future.get() 拿到 AuthResult                        │
  └─ callback(AuthResult) ──────────────────────────────────┘
     Provider 根据 mergedAuthStrategy 执行阻断/放行
```

---

## 五、Demo 完整代码

```cpp
/*
 * auth_provider_demo.cpp — 阻断服务提供者 C++ 接入示例
 *
 * 编译依赖（BUILD.gn）:
 *   external_deps += [
 *     "security_guard:libsg_collect_sdk",
 *     "cJSON:cjson",
 *     "ffrt:libffrt",
 *     "hilog:libhilog",
 *     "ipc:ipc_core",
 *     "samgr:samgr_proxy",
 *   ]
 *   defines += [ "SECURITY_GUARD_AUTH_EVENT_ENABLE" ]
 */

#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "auth_client_info.h"
#include "auth_client_status.h"
#include "auth_event_info.h"
#include "auth_provider_subscribe_client.h"
#include "auth_result.h"
#include "auth_strategy.h"
#include "security_guard_log.h"

using namespace OHOS::Security::SecurityGuard;

// ============================================================================
// 事件 ID 定义（与 Client 侧约定一致）
// ============================================================================
constexpr int64_t EVENT_FILE_DOWNLOAD   = 100001;  // 文件下载阻断事件
constexpr int64_t EVENT_APP_INSTALL     = 100002;  // 应用安装阻断事件
constexpr int64_t EVENT_NETWORK_ACCESS  = 100003;  // 网络访问阻断事件

// ============================================================================
// Demo 主类：封装 Provider 生命周期与阻断业务逻辑
// ============================================================================
class AuthProviderDemo {
public:
    AuthProviderDemo() = default;
    ~AuthProviderDemo() { Destroy(); }

    // ------------------------------------------------------------------
    // 步骤 1：初始化 — 创建 Provider 会话
    // ------------------------------------------------------------------
    bool Init()
    {
        // 注册 onClientStatusChanged 回调
        // 创建成功后框架立即回调一次，下发当前全量 Client 列表
        AuthProviderCallback callback = [this](const std::vector<AuthClientInfo> &clientsInfo) {
            OnClientStatusChanged(clientsInfo);
        };

        int32_t ret = AuthProviderSubscribeClient::CreateProvider(callback, "demo_auth_provider", provider_);
        if (ret != SUCCESS || provider_ == nullptr) {
            SGLOGE("CreateProvider failed, ret=%{public}d", ret);
            return false;
        }
        SGLOGI("CreateProvider success, serviceId=demo_auth_provider");
        return true;
    }

    // ------------------------------------------------------------------
    // 步骤 2：阻断决策 — 查询阻断策略并执行阻断/放行
    // ------------------------------------------------------------------
    // 场景：文件下载场景，Provider 需要询问各客户端是否允许下载
    void CheckFileDownload(const std::string &filePath)
    {
        if (provider_ == nullptr) {
            SGLOGE("provider not initialized");
            return;
        }

        // 构造事件信息（content 为 JSON 字符串，由 Provider 自定义格式）
        std::string content = R"({"action":"file_download","path":")" + filePath + R"(","size":1024})";
        AuthEventInfo event(EVENT_FILE_DOWNLOAD, "1.0", content);

        // 调用 RequestAuthResult（kit 内部 promise/future 同步等待，最多 400ms）
        int32_t ret = provider_->RequestAuthResult(event, [this, filePath](const AuthResult &result) {
            HandleAuthResult(result, "file_download:" + filePath);
        });

        if (ret != SUCCESS) {
            SGLOGE("RequestAuthResult failed, ret=%{public}d, fallback to allow", ret);
            // 请求未受理（如并发超限），Provider 自行决定兜底策略
            // 此处选择放行（不阻断业务），也可根据业务需要改为阻断
            AllowFileDownload(filePath);
        }
        // 注意：RequestAuthResult 返回后，回调可能在同一线程同步触发（kit 同步等待）
        // 也可能稍后触发（超时路径），Provider 需确保回调中不阻塞
    }

    // ------------------------------------------------------------------
    // 步骤 3：客户端降级 — 对指定 Client 只通知不参与决策
    // ------------------------------------------------------------------
    // 场景：某客户端已知不响应（如处于后台），标记为降级，只推送事件不等待其回填
    void CheckWithDegradedClient(const std::string &filePath, const std::string &degradedClientId)
    {
        if (provider_ == nullptr) {
            return;
        }

        AuthEventInfo event(EVENT_FILE_DOWNLOAD, "1.0",
            R"({"action":"file_download_degraded","path":")" + filePath + R"("})");

        // 构造降级客户端状态列表
        std::vector<AuthClientStatus> clientStatus;
        clientStatus.emplace_back(degradedClientId, true);  // isDegraded=true

        event.SetClientStatus(clientStatus);

        provider_->RequestAuthResult(event, [this, filePath](const AuthResult &result) {
            HandleAuthResult(result, "file_download_degraded:" + filePath);
        });
    }

    // ------------------------------------------------------------------
    // 步骤 4：并发阻断 — 多业务线程同时查询
    // ------------------------------------------------------------------
    // 场景：多个文件同时下载，各线程独立查询阻断策略
    // 每 Provider 并发上限 128，超限返回 27000004
    void ConcurrentCheck(const std::vector<std::string> &filePaths)
    {
        if (provider_ == nullptr) {
            return;
        }

        std::vector<std::thread> threads;
        for (const auto &path : filePaths) {
            threads.emplace_back([this, path]() {
                AuthEventInfo event(EVENT_FILE_DOWNLOAD, "1.0",
                    R"({"action":"concurrent","path":")" + path + R"("})");
                int32_t ret = provider_->RequestAuthResult(event,
                    [this, path](const AuthResult &result) {
                        HandleAuthResult(result, "concurrent:" + path);
                    });
                if (ret != SUCCESS) {
                    SGLOGE("concurrent RequestAuthResult failed for %s, ret=%d", path.c_str(), ret);
                }
            });
        }
        for (auto &t : threads) {
            t.join();
        }
    }

    // ------------------------------------------------------------------
    // 步骤 5：销毁
    // ------------------------------------------------------------------
    void Destroy()
    {
        if (provider_ != nullptr) {
            provider_->DeleteProvider();
            provider_ = nullptr;
            SGLOGI("Provider destroyed");
        }
    }

private:
    std::shared_ptr<AuthProviderSubscribeClient> provider_;

    // ------------------------------------------------------------------
    // 回调：客户端状态变更（Client 创建/销毁/订阅变更/降级）
    // ------------------------------------------------------------------
    void OnClientStatusChanged(const std::vector<AuthClientInfo> &clientsInfo)
    {
        SGLOGI("ClientStatusChanged, client count=%{public}zu", clientsInfo.size());
        for (const auto &info : clientsInfo) {
            SGLOGI("  clientId=%{public}s, events=%{public}zu, timeoutStrategy=%{public}d",
                info.GetClientId().c_str(),
                info.GetSubscribedEvents().size(),
                static_cast<int32_t>(info.GetDefaultTimeoutStrategy()));
        }
        // Provider 可在此缓存客户端列表，用于后续降级操作时指定 clientId
    }

    // ------------------------------------------------------------------
    // 回调：阻断结果处理 — 根据聚合策略执行阻断或放行
    // ------------------------------------------------------------------
    void HandleAuthResult(const AuthResult &result, const std::string &context)
    {
        AuthStrategy strategy = result.GetMergedAuthStrategy();
        SGLOGI("AuthResult: context=%{public}s, mergedStrategy=%{public}d",
            context.c_str(), static_cast<int32_t>(strategy));

        // 打印每个客户端的明细策略
        for (const auto &cr : result.GetClientAuthResult()) {
            SGLOGI("  client=%{public}s, strategy=%{public}d",
                cr.GetClientId().c_str(), static_cast<int32_t>(cr.GetAuthStrategy()));
        }

        // 【关键】根据聚合策略执行阻断或放行
        switch (strategy) {
            case AuthStrategy::DENY:
                // 从严策略：至少一个客户端判定为阻断 → 执行阻断
                DoBlock(context, result);
                break;
            case AuthStrategy::ALLOW:
                // 全部客户端放行 → 执行放行
                DoAllow(context, result);
                break;
            case AuthStrategy::TIMEOUT:
                // kit 侧 400ms 超时兜底 → 按业务策略处置
                // 此处选择放行（避免超时导致业务卡死），也可改为阻断
                SGLOGW("timeout fallback, allowing: %{public}s", context.c_str());
                DoAllow(context, result);
                break;
            default:
                SGLOGE("unknown strategy, default allow");
                DoAllow(context, result);
                break;
        }
    }

    // ------------------------------------------------------------------
    // 业务动作：阻断
    // ------------------------------------------------------------------
    void DoBlock(const std::string &context, const AuthResult &result)
    {
        SGLOGI("【BLOCK】executing block: %{public}s", context.c_str());
        // TODO: 执行实际阻断动作
        // - 中断文件下载
        // - 拦截应用安装
        // - 断开网络连接
        // - 记录安全日志
    }

    // ------------------------------------------------------------------
    // 业务动作：放行
    // ------------------------------------------------------------------
    void DoAllow(const std::string &context, const AuthResult &result)
    {
        SGLOGI("【ALLOW】executing allow: %{public}s", context.c_str());
        // TODO: 执行实际放行动作
        // - 继续文件下载
        // - 允许应用安装
        // - 放行网络访问
    }

    void AllowFileDownload(const std::string &filePath)
    {
        SGLOGI("【ALLOW】fallback allow file download: %{public}s", filePath.c_str());
    }
};

// ============================================================================
// 使用示例 — main 函数
// ============================================================================
// int main()
// {
//     AuthProviderDemo demo;
//
//     // 步骤1：初始化
//     if (!demo.Init()) {
//         return -1;
//     }
//
//     // 等待客户端接入（实际场景中客户端通过 createAuthEventClient 订阅事件）
//     std::this_thread::sleep_for(std::chrono::seconds(2));
//
//     // 步骤2：阻断决策 — 查询文件下载策略
//     demo.CheckFileDownload("/data/test/sample.apk");
//
//     // 步骤3：降级操作 — 对特定客户端只通知不参与决策
//     demo.CheckWithDegradedClient("/data/test/sample2.apk", "client_abc123");
//
//     // 步骤4：并发阻断
//     std::vector<std::string> files = {"/data/f1", "/data/f2", "/data/f3"};
//     demo.ConcurrentCheck(files);
//
//     // 步骤5：销毁
//     demo.Destroy();
//     return 0;
// }
```

## 六、关键节点说明

### 6.1 阻断与放行的决策边界

```
框架聚合结果          Provider 执行动作
─────────────────────────────────────────
mergedAuthStrategy    DENY     → DoBlock()   执行阻断
                      ALLOW    → DoAllow()   执行放行
                      TIMEOUT  → 业务自定义   (kit 超时兜底)
```

**Provider 不参与策略决策**，只执行框架聚合后的最终结果。从严策略由框架保证：
- 任一 Client 回填 DENY → 框架立即返回 DENY（不等其余 Client）
- 全部 Client 回填 ALLOW → 框架返回 ALLOW
- 超时未回填 → 按 Client 的 `defaultTimeoutStrategy` 处置

### 6.2 降级操作的语义

```cpp
// 降级客户端：isDegraded=true
AuthClientStatus status(clientId, true);
event.SetClientStatus({status});
```

| 维度 | 正常客户端 | 降级客户端 |
|---|---|---|
| 收到事件 | ✅ | ✅ |
| 参与从严聚合 | ✅ 计入 sentClientCount | ❌ 不计数 |
| 需要回填结果 | ✅ 必须回填 | ❌ 不需要回填 |
| 出现在 AuthResult.clientAuthResult | ✅ | ❌ |
| 超时影响结果 | ✅（DENY 超时则阻断） | ❌ |

**使用场景**：Provider 已知某客户端无法响应（后台冻结、已知故障），但仍希望其感知事件，此时标记降级。

### 6.3 同步等待与超时

```
provider->RequestAuthResult(event, callback)
    │
    ├─ ret != SUCCESS → 请求未受理（并发超限/Provider无效）
    │   → Provider 自行兜底（建议放行避免业务卡死）
    │
    └─ ret == SUCCESS → kit 内部 promise/future.wait_for(400ms)
        ├─ 400ms 内回调 → callback(AuthResult) 拿到真实聚合结果
        └─ 400ms 超时   → callback(AuthResult{TIMEOUT}) kit 兜底
```

**注意**：`RequestAuthResult` 返回后回调**可能尚未触发**（SA 侧仍在聚合中）。但由于 kit 内部 `future.wait_for(400ms)` 同步等待，实际返回时回调已触发。Provider 在 `RequestAuthResult` 返回后可安全操作。

### 6.4 clientId 获取方式

降级操作需要指定 `clientId`。获取途径：

1. **`onClientStatusChanged` 回调**：框架创建 Provider 后立即回调全量 Client 列表，Client 订阅/取消订阅/销毁时也会回调。Provider 应缓存此列表。
2. **`AuthResult.clientAuthResult`**：每次阻断结果中包含参与聚合的 Client 的 `clientId`，可用于后续降级。

### 6.5 错误码处理

| 返回码 | 含义 | Provider 处置建议 |
|---|---|---|
| SUCCESS(0) | 请求已受理 | 等回调拿结果 |
| 201 | 无权限 | 检查权限配置 |
| 202 | 非系统应用 | 检查系统应用配置 |
| 27000001 | 内部错误 | 重试或放行兜底 |
| 27000002 | 进程内 Provider 超限 | 确保每进程仅 1 个 Provider |
| 27000003 | 全局 Provider 超限 | 确保设备不超过 16 个 Provider |
| 27000004 | 并发请求超限(>128) | 降低并发或排队重试 |

### 6.6 线程安全

- `RequestAuthResult` 可多线程并发调用（每 Provider 上限 128 并发）
- `onClientStatusChanged` 回调可能在工作线程触发，不要在回调中阻塞或调用 `RequestAuthResult`
- `DeleteProvider` 幂等，但建议在所有 `RequestAuthResult` 完成后再销毁
