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
#include <set>
#include <string>
#include <vector>

#include "ffrt.h"
#include "iremote_object.h"
#include "nocopyable.h"

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
constexpr int64_t AUTH_RESULT_TIMEOUT_MS = 400;
constexpr const char* AUTH_SERVICE_ACCESS_PERMISSION = "ohos.permission.AUTH_SERVICE_ACCESS";

class AuthCoordinator {
public:
    static AuthCoordinator& GetInstance();

    int32_t CreateAuthProvider(pid_t callerPid, int32_t callerUid, const sptr<IRemoteObject> &callback,
        const std::string &serviceId, sptr<IRemoteObject> &providerRemote);
    void DestroyAuthProvider(AuthProviderSessionService *provider);
    int32_t RequestAuthResult(AuthProviderSessionService *provider, const AuthEventInfo &event,
        const sptr<IRemoteObject> &resultCallback, AuthResult &result);
    int32_t SetAuthResult(AuthEventSessionService *session, const AuthEvent &event, bool allowFlag, int64_t seqnum);
    void RemoveProvider(const sptr<AuthProviderSessionService> &provider);
    void NotifyClientsStatusChanged();
    static int32_t IsProviderAllowed();

private:
    // 事件路由上下文 — 按 seqnum 索引，每个客户端独立 seqnum，聚合完成后移除
    // 等待机制: promise/future（非 condition_variable），promise 被写入值后解除阻塞
    struct RoutingContext {
        int64_t eventId {0};
        size_t sentClientCount {0};
        size_t defaultDenyCount {0};
        std::map<std::string, AuthStrategy> clientResults;          // clientId → 回填策略
        std::map<std::string, AuthStrategy> clientTimeoutStrategies; // clientId → 超时处置策略
        std::map<std::string, std::shared_ptr<ffrt::promise<AuthStrategy>>> clientPromises; // clientId → promise
        std::shared_ptr<ffrt::promise<AuthResult>> resultPromise;   // 最终结果 promise
        ffrt::mutex ctxMutex;                                       // ffrt 锁，不混用 std mutex
        std::atomic<bool> completed {false};
        AuthStrategy mergedAuthStrategy {AuthStrategy::ALLOW};
    };

    // DispatchEventToClients 的输出参数集合（控制入参 ≤5）
    struct DispatchResult {
        std::vector<int64_t> seqnums;
        std::vector<std::string> clientIds;
    };

    AuthCoordinator();
    ~AuthCoordinator();
    DISALLOW_COPY_AND_MOVE(AuthCoordinator);

    int32_t CheckProviderQuotaLocked(pid_t callerPid) const;
    std::set<sptr<AuthProviderSessionService>>::iterator FindProviderLocked(
        AuthProviderSessionService *provider);
    void RemoveProviderLocked(const sptr<AuthProviderSessionService> &provider);
    void DispatchEventToClients(int64_t eventId, int64_t providerUid,
        const std::vector<AuthClientStatus> &clientStatusList,
        RoutingContext &ctx, DispatchResult &result);
    void HandleTimeout(RoutingContext &ctx);
    void WaitForCompletion(RoutingContext &ctx, AuthResult &result,
        int64_t seqnum, const std::vector<int64_t> &seqnums);
    void BuildAuthResult(RoutingContext &ctx, AuthResult &result);
    void NotifyAuthResult(const sptr<IRemoteObject> &callback, const AuthResult &result);
    void ReportTimeoutHA(int64_t eventId, const std::string &clientId, int64_t timeoutMs);
    std::vector<AuthClientInfo> CollectClientInfos();

    ffrt::mutex mutex_{};
    std::set<sptr<AuthProviderSessionService>> providerSessions_{};
    std::map<int64_t, RoutingContext> routingContexts_{};  // 按 seqnum 索引
    std::map<int64_t, int64_t> seqnumToEventId_{};         // seqnum → eventId
    std::atomic<int64_t> seqCounter_ {0};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
#endif // SECURITY_GUARD_AUTH_COORDINATOR_H
