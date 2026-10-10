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

#ifndef SECURITY_GUARD_AUTH_COORDINATOR_H
#define SECURITY_GUARD_AUTH_COORDINATOR_H
#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE

#include <atomic>
#include <cstdint>
#include <future>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "ffrt.h"
#include "iremote_object.h"
#include "nocopyable.h"

#include "auth_client_info.h"
#include "auth_event.h"
#include "auth_event_info.h"
#include "auth_event_session_service.h"
#include "auth_result.h"
#include "auth_strategy.h"
#include "auth_provider_session_service.h"

namespace OHOS::Security::SecurityGuard {
constexpr size_t MAX_AUTH_PROVIDER_SIZE_ONE_PROCESS = 1;
constexpr size_t MAX_AUTH_PROVIDER_SIZE = 16;
constexpr size_t MAX_AUTH_REQUEST_CONCURRENT = 16;
constexpr const char* AUTH_SERVICE_ACCESS_PERMISSION = "ohos.permission.AUTH_SERVICE_ACCESS";

class AuthCoordinator {
public:
    static AuthCoordinator& GetInstance();

    int32_t CreateAuthProvider(pid_t callerPid, int32_t callerUid, const sptr<IRemoteObject> &callback,
        const std::string &serviceId, sptr<IRemoteObject> &providerRemote);
    void DestroyAuthProvider(AuthProviderSessionService *provider);
    // IPC 异步应答: 返回码承载校验结果（是否接受请求），最终阻断策略经 resultCallback 回调返回
    int32_t RequestAuthResult(AuthProviderSessionService *provider, const AuthEventInfo &event,
        const sptr<IRemoteObject> &resultCallback);
    int32_t SetAuthResult(AuthEventSessionService *session, const AuthEvent &event, int32_t authStrategy);
    void RemoveProvider(const sptr<AuthProviderSessionService> &provider);
    void NotifyClientStatusChanged();
    static int32_t IsProviderAllowed();

private:
    // 事件路由上下文 — 按 eventId 索引，聚合完成后移除
    // clientId: 客户端唯一标识（ConstructClientId 生成），用于结果聚合
    // seqnum: 每客户端每事件独有，用于路由查找
    struct RoutingContext {
        int64_t eventId {0};
        size_t sentClientCount {0};
        size_t defaultDenyCount {0};
        std::map<std::string, AuthStrategy> clientResults;          // clientId → 回填策略
        std::map<std::string, AuthStrategy> clientTimeoutStrategies; // clientId → 超时策略
        std::map<std::string, std::shared_ptr<std::promise<AuthStrategy>>> clientPromises; // clientId → promise
        std::shared_ptr<std::promise<AuthResult>> resultPromise;
        ffrt::mutex ctxMutex;
        bool completed {false};
        AuthStrategy mergedAuthStrategy {AuthStrategy::ALLOW};
    };

    // DispatchEventToClients 的输出参数集合（控制入参 ≤5）
    struct DispatchResult {
        std::vector<int64_t> seqnums;
        std::vector<std::string> clientIds;  // 与 seqnums 一一对应，用于清理 seqnumKey
    };

    AuthCoordinator();
    ~AuthCoordinator();
    DISALLOW_COPY_AND_MOVE(AuthCoordinator);

    int32_t CheckProviderQuotaLocked(pid_t callerPid) const;
    std::set<sptr<AuthProviderSessionService>>::iterator FindProviderLocked(
        AuthProviderSessionService *provider);
    void RemoveProviderLocked(const sptr<AuthProviderSessionService> &provider);
    // DispatchEventToClients 入参超过 5，用结构体收拢
    struct DispatchParams {
        int64_t requestId;
        int64_t eventId;
        const std::vector<AuthClientStatus> &clientStatusList;
        RoutingContext &ctx;
        DispatchResult &result;
    };
    void DispatchEventToClients(const DispatchParams &params);
    void NotifyDegradedClient(int64_t eventId, AuthEventSessionService *session);
    void RegisterNormalClient(int64_t requestId, int64_t eventId, AuthEventSessionService *session,
        RoutingContext &ctx, DispatchResult &result,
        std::vector<std::pair<sptr<IRemoteObject>, AuthStrategy>> &targets);
    void PushEventsToClients(int64_t eventId,
        const std::vector<std::pair<sptr<IRemoteObject>, AuthStrategy>> &targets,
        const DispatchResult &result);
    void DecrementCounters(RoutingContext &ctx, const std::string &clientId);
    void EvaluateStrictPolicy(RoutingContext &ctx, AuthStrategy authStrategy, int64_t eventId);
    void HandleTimeout(RoutingContext &ctx);
    void RegisterRoutingContext(int64_t requestId, RoutingContext &ctx);
    void SubmitAsyncWait(int64_t requestId, std::vector<int64_t> &&seqnums,
        std::vector<std::string> &&clientIds, const sptr<IRemoteObject> &resultCallback);
    void WaitForCompletion(RoutingContext &ctx, AuthResult &result,
        int64_t requestId, const std::vector<int64_t> &seqnums,
        const std::vector<std::string> &clientIds);
    void BuildAuthResult(RoutingContext &ctx, AuthResult &result);
    void NotifyAuthResult(const sptr<IRemoteObject> &callback, const AuthResult &result);
    void ReportTimeoutHA(int64_t eventId, int64_t seqnum, int64_t timeoutMs);
    std::vector<AuthClientInfo> CollectClientInfos();

    // seqnum per-client 递增，不同客户端可能相同，用 clientId+seqnum 组合 key 查找
    // 组合 key 格式: clientId + "_" + seqnum
    static std::string MakeSeqnumKey(const std::string &clientId, int64_t seqnum);

    ffrt::mutex mutex_{};
    std::set<sptr<AuthProviderSessionService>> providerSessions_{};
    std::map<int64_t, std::unique_ptr<RoutingContext>> routingContexts_{};  // requestId → ctx
    std::map<std::string, int64_t> seqnumToRequestId_{};  // clientId_seqnum → requestId
    std::map<std::string, AuthEventSessionService *> seqnumToSession_{}; // clientId_seqnum → session
    std::atomic<int64_t> requestCounter_ {0};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
#endif // SECURITY_GUARD_AUTH_COORDINATOR_H
