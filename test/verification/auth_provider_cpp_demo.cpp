/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// ============================================================================
// 阻断服务提供者（Provider）C++ 接口使用 Demo — 源文件
//
// 本文件演示阻断服务提供者如何通过 C++ inner_api 接入阻断框架：
//   - 阻断决策：查询阻断策略，拿到 DENY 后执行阻断
//   - 放行决策：查询阻断策略，拿到 ALLOW 后执行放行
//   - 客户端降级：对指定客户端只通知不参与决策
//
// 编译依赖（BUILD.gn）：
//   external_deps += [
//     "security_guard:libsg_collect_sdk",
//     "cJSON:cjson",
//     "ffrt:libffrt",
//     "hilog:libhilog",
//     "ipc:ipc_core",
//     "samgr:samgr_proxy",
//   ]
//   defines += [ "SECURITY_GUARD_AUTH_EVENT_ENABLE" ]
// ============================================================================

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
#include "security_guard_define.h"
#include "security_guard_log.h"

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
using namespace OHOS::Security::SecurityGuard;

// ============================================================================
// 事件 ID 定义（与 Client 侧约定一致，Client 通过 Subscribe(eventId) 订阅）
// ============================================================================
constexpr int64_t EVENT_FILE_DOWNLOAD  = 100001;  // 文件下载阻断事件
constexpr int64_t EVENT_APP_INSTALL    = 100002;  // 应用安装阻断事件
constexpr int64_t EVENT_NETWORK_ACCESS = 100003;  // 网络访问阻断事件

// ============================================================================
// Demo 主类：封装 Provider 生命周期与阻断业务逻辑
// ============================================================================
class AuthProviderDemo {
public:
    AuthProviderDemo() = default;
    ~AuthProviderDemo() { Destroy(); }

    // ========================================================================
    // 步骤 1：初始化 — 创建 Provider 会话
    // ========================================================================
    // 调用 CreateProvider，注册 onClientStatusChanged 回调。
    // 创建成功后框架立即回调一次，下发当前全量 Client 列表。
    // Provider 应缓存客户端列表，供后续降级操作指定 clientId。
    // ========================================================================
    bool Init()
    {
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

    // ========================================================================
    // 步骤 2：阻断决策 — 查询阻断策略并执行阻断/放行
    // ========================================================================
    // 场景：文件下载场景，Provider 需要询问各客户端是否允许下载。
    // - RequestAuthResult 内部 promise/future 同步等待，最多阻塞 400ms
    // - 框架 ffrt 异步任务：推送事件 → Client 回填 → 从严聚合
    // - 聚合完成后经 callback 返回 AuthResult
    // - Provider 根据 mergedAuthStrategy 执行阻断或放行
    // ========================================================================
    void CheckFileDownload(const std::string &filePath)
    {
        if (provider_ == nullptr) {
            SGLOGE("provider not initialized");
            return;
        }

        // 构造事件信息（content 为 JSON 字符串，格式由 Provider 自定义）
        std::string content = R"({"action":"file_download","path":")" + filePath +
                              R"(","size":1024})";
        AuthEventInfo event(EVENT_FILE_DOWNLOAD, "1.0", content);

        // 调用 RequestAuthResult（kit 内部 promise/future 同步等待，最多 400ms）
        int32_t ret = provider_->RequestAuthResult(event,
            [this, filePath](const AuthResult &result) {
                HandleAuthResult(result, "file_download:" + filePath);
            });

        if (ret != SUCCESS) {
            SGLOGE("RequestAuthResult failed, ret=%{public}d, fallback to allow", ret);
            // 请求未受理（如并发超限 27000004），Provider 自行决定兜底策略
            // 此处选择放行（不阻断业务），也可根据业务需要改为阻断
            DoAllow("file_download:" + filePath, AuthResult());
        }
        // 注意：RequestAuthResult 返回后，回调已在同一线程同步触发（kit 同步等待）
    }

    // ========================================================================
    // 步骤 3：客户端降级 — 对指定 Client 只通知不参与决策
    // ========================================================================
    // 场景：某客户端已知不响应（后台冻结/已知故障），标记为降级。
    // 降级客户端：收到事件通知，但不计入聚合计数，不需要回填，不影响最终结果。
    // ========================================================================
    void CheckWithDegradedClient(const std::string &filePath, const std::string &degradedClientId)
    {
        if (provider_ == nullptr) {
            return;
        }

        AuthEventInfo event(EVENT_FILE_DOWNLOAD, "1.0",
            R"({"action":"file_download_degraded","path":")" + filePath + R"("})");

        // 构造降级客户端状态列表：isDegraded=true
        std::vector<AuthClientStatus> clientStatus;
        clientStatus.emplace_back(degradedClientId, true);  // 【关键】isDegraded=true
        event.SetClientStatus(clientStatus);

        provider_->RequestAuthResult(event, [this, filePath](const AuthResult &result) {
            HandleAuthResult(result, "file_download_degraded:" + filePath);
        });
    }

    // ========================================================================
    // 步骤 4：并发阻断 — 多业务线程同时查询
    // ========================================================================
    // 场景：多个文件同时下载，各线程独立查询阻断策略。
    // 每 Provider 并发上限 128，超限返回 27000004。
    // ========================================================================
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
                    SGLOGE("concurrent RequestAuthResult failed for %{public}s, ret=%{public}d",
                        path.c_str(), ret);
                    // 并发超限时兜底放行
                    DoAllow("concurrent:" + path, AuthResult());
                }
            });
        }
        for (auto &t : threads) {
            t.join();
        }
    }

    // ========================================================================
    // 步骤 5：销毁
    // ========================================================================
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
    // 缓存当前客户端列表，供降级操作查询 clientId
    std::vector<AuthClientInfo> cachedClients_;
    ffrt::mutex clientsMutex_;

    // ========================================================================
    // 回调：客户端状态变更
    // ========================================================================
    // 触发时机：Client 创建/销毁/订阅变更/降级
    // 框架异步通知，不阻塞 Client 侧操作。
    // Provider 应缓存客户端列表，用于后续降级操作指定 clientId。
    // ========================================================================
    void OnClientStatusChanged(const std::vector<AuthClientInfo> &clientsInfo)
    {
        SGLOGI("ClientStatusChanged, client count=%{public}zu", clientsInfo.size());
        {
            std::lock_guard<ffrt::mutex> lock(clientsMutex_);
            cachedClients_ = clientsInfo;
        }
        for (const auto &info : clientsInfo) {
            SGLOGI("  clientId=%{public}s, events=%{public}zu, timeoutStrategy=%{public}d, timeoutMs=%{public}d",
                info.GetClientId().c_str(),
                info.GetSubscribedEvents().size(),
                static_cast<int32_t>(info.GetDefaultTimeoutStrategy()),
                info.GetDefaultTimeoutMs());
        }
    }

    // ========================================================================
    // 回调：阻断结果处理 — 根据聚合策略执行阻断或放行
    // ========================================================================
    // 【核心】Provider 不参与策略决策，只执行框架聚合后的最终结果。
    // 从严策略由框架保证：
    //   - 任一 Client 回填 DENY → 框架立即返回 DENY（不等其余 Client）
    //   - 全部 Client 回填 ALLOW → 框架返回 ALLOW
    //   - 超时未回填 → 按 Client 的 defaultTimeoutStrategy 处置
    // ========================================================================
    void HandleAuthResult(const AuthResult &result, const std::string &context)
    {
        AuthStrategy strategy = result.GetMergedAuthStrategy();
        SGLOGI("AuthResult: context=%{public}s, mergedStrategy=%{public}d",
            context.c_str(), static_cast<int32_t>(strategy));

        // 打印每个参与聚合的客户端明细策略
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

    // ========================================================================
    // 业务动作：阻断
    // ========================================================================
    void DoBlock(const std::string &context, const AuthResult &result)
    {
        SGLOGI("【BLOCK】executing block: %{public}s", context.c_str());
        // TODO: 执行实际阻断动作，例如：
        //   - 中断文件下载
        //   - 拦截应用安装
        //   - 断开网络连接
        //   - 上报安全事件/记录日志
    }

    // ========================================================================
    // 业务动作：放行
    // ========================================================================
    void DoAllow(const std::string &context, const AuthResult &result)
    {
        SGLOGI("【ALLOW】executing allow: %{public}s", context.c_str());
        // TODO: 执行实际放行动作，例如：
        //   - 继续文件下载
        //   - 允许应用安装
        //   - 放行网络访问
    }

    // ========================================================================
    // 辅助：获取缓存中第一个订阅了指定事件的客户端 clientId（用于降级示例）
    // ========================================================================
    std::string GetFirstSubscribedClientId(int64_t eventId)
    {
        std::lock_guard<ffrt::mutex> lock(clientsMutex_);
        for (const auto &info : cachedClients_) {
            auto events = info.GetSubscribedEvents();
            if (std::find(events.begin(), events.end(), eventId) != events.end()) {
                return info.GetClientId();
            }
        }
        return "";
    }
};

// ============================================================================
// 使用示例 — main 函数（实际场景中由业务事件触发）
// ============================================================================
// 注：以下为伪 main，实际运行需在 OpenHarmony 设备上作为系统服务运行
// ============================================================================
/*
int main()
{
    AuthProviderDemo demo;

    // 步骤1：初始化 — 创建 Provider 会话
    if (!demo.Init()) {
        SGLOGE("init failed");
        return -1;
    }

    // 等待客户端接入（实际场景中客户端通过 createAuthEventClient 订阅事件）
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // 步骤2：阻断决策 — 查询文件下载策略
    //   框架会推送事件给所有订阅了 EVENT_FILE_DOWNLOAD 的 Client
    //   任一 Client 回填 DENY → demo 收到 DENY → 执行阻断
    //   全部 Client 回填 ALLOW → demo 收到 ALLOW → 执行放行
    demo.CheckFileDownload("/data/test/sample.apk");

    // 步骤3：降级操作 — 对特定客户端只通知不参与决策
    //   degradedClientId 可从 OnClientStatusChanged 回调中获取
    demo.CheckWithDegradedClient("/data/test/sample2.apk", "client_abc123");

    // 步骤4：并发阻断 — 多线程同时查询
    std::vector<std::string> files = {"/data/f1", "/data/f2", "/data/f3"};
    demo.ConcurrentCheck(files);

    // 步骤5：销毁
    demo.Destroy();
    return 0;
}
*/
#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
