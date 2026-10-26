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
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "ffrt.h"
#include "ffrt_inner.h"
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
constexpr size_t MAX_AUTH_REQUEST_CONCURRENT_PER_PROVIDER = 128;
constexpr const char* AUTH_SERVICE_ACCESS_PERMISSION = "ohos.permission.AUTH_SERVICE_ACCESS";
// P1-3: seqnum 索引分片数，降低高并发下锁竞争
constexpr size_t SEQNUM_SHARD_COUNT = 16;

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
        int64_t beginTime {0};
        std::string eventContent;      // M12: 原始事件内容，供超时 HA 打点
        std::string eventMetadata;     // M12: 原始事件 metadata，供超时 HA 打点
        size_t sentClientCount {0};
        size_t defaultDenyCount {0};
        std::map<std::string, AuthStrategy> clientResults;          // clientId → 回填策略
        std::map<std::string, AuthStrategy> clientTimeoutStrategies; // clientId → 超时策略
        std::map<std::string, std::shared_ptr<ffrt::promise<AuthStrategy>>> clientPromises; // clientId → promise
        // M12: per-client 应用信息，供超时 HA 打点（应用信息+事件信息+超时时间）
        struct ClientAppInfo {
            pid_t pid {0};
            int32_t uid {0};
            int64_t seqnum {0};
        };
        std::map<std::string, ClientAppInfo> clientAppInfos;  // clientId → pid/uid/seqnum
        std::shared_ptr<ffrt::promise<AuthResult>> resultPromise;
        ffrt::mutex ctxMutex;
        bool completed {false};
        bool resultPromiseSatisfied {false};
        std::set<std::string> satisfiedClientIds;
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
        const AuthEventInfo &eventInfo;
        RoutingContext &ctx;
        DispatchResult &result;
        std::shared_ptr<RoutingContext> ctxPtr;  // P0-1: 传递给 RegisterNormalClient 写入分片索引
    };
    void DispatchEventToClients(const DispatchParams &params);
    void NotifyDegradedClient(const AuthEventInfo &eventInfo, AuthEventSessionService *session);
    // RegisterNormalClient: 入参收拢到 DispatchParams，避免超过 5 个入参
    void RegisterNormalClient(const DispatchParams &params, AuthEventSessionService *session,
        std::vector<std::pair<sptr<IRemoteObject>, AuthStrategy>> &targets);
    void PushEventsToClients(const AuthEventInfo &eventInfo,
        const std::vector<std::pair<sptr<IRemoteObject>, AuthStrategy>> &targets,
        const DispatchResult &result);
    void DecrementCounters(RoutingContext &ctx, const std::string &clientId);
    void EvaluateStrictPolicy(RoutingContext &ctx, AuthStrategy authStrategy, int64_t eventId);
    // 拆分 HandleTimeout: 超时单个 client 处置 + 聚合结果通知，避免单函数超过 50 行
    void HandleTimeoutClient(RoutingContext &ctx, const std::string &clientId, AuthStrategy strategy);
    void NotifyTimeoutResult(RoutingContext &ctx, const std::string &clientId);
    void SatisfyResultPromise(RoutingContext &ctx);
    // P0-2: HandleTimeout 全程持 ctxMutex，避免与 SetAuthResult 数据竞争
    void HandleTimeout(std::shared_ptr<RoutingContext> ctxPtr);
    // 拆分 SetAuthResult: 查找 ctx + 回填策略 + HA 打点，避免单函数超过 50 行
    std::shared_ptr<RoutingContext> FindRoutingContext(const std::string &clientId, int64_t seqnum);
    void RecordClientResult(RoutingContext &ctx, const std::string &clientId, AuthStrategy strategy);
    void ReportDenyResult(const RoutingContext &ctx, const std::string &clientId);
    // P0-3: ffrt 任务捕获 sptr<AuthProviderSessionService>，避免 provider 析构后 UAF
    void ProcessAuthResultAsync(sptr<AuthProviderSessionService> provider, int64_t requestId,
        const AuthEventInfo &event, const sptr<IRemoteObject> &resultCallback);
    // P0-1: WaitForCompletion 持有 shared_ptr 保证 ctx 存活，wait_for 不持锁
    void WaitForCompletion(std::shared_ptr<RoutingContext> ctxPtr, AuthResult &result,
        int64_t requestId, const std::vector<int64_t> &seqnums,
        const std::vector<std::string> &clientIds);
    void BuildAuthResult(RoutingContext &ctx, AuthResult &result);
    void NotifyAuthResult(const sptr<IRemoteObject> &callback, const AuthResult &result);
    std::vector<AuthClientInfo> CollectClientInfos();
    // P1-3: 按 hash(seqnumKey) 分片，返回对应分片索引
    static size_t GetSeqnumShardIndex(const std::string &seqnumKey);

    // seqnum per-client 递增，不同客户端可能相同，用 clientId+seqnum 组合 key 查找
    // 组合 key 格式: clientId + "_" + seqnum
    static std::string MakeSeqnumKey(const std::string &clientId, int64_t seqnum);

    ffrt::mutex mutex_{};
    std::set<sptr<AuthProviderSessionService>> providerSessions_{};
    // P0-1: unique_ptr → shared_ptr，SetAuthResult 持拷贝延长生命周期，避免 erase 后 UAF
    std::map<int64_t, std::shared_ptr<RoutingContext>> routingContexts_{};  // requestId → ctx
    // P1-3: seqnumKey → ctx 分片索引，替代原 seqnumToRequestId_ + routingContexts_ 两级查找
    // 每 SetAuthResult 只需锁对应分片（~2μs），替代原全局 mutex_（~30μs）
    struct SeqnumShard {
        ffrt::mutex mutex;
        std::map<std::string, std::shared_ptr<RoutingContext>> seqnumToCtx;
    };
    SeqnumShard seqnumShards_[SEQNUM_SHARD_COUNT];
    std::atomic<int64_t> requestCounter_ {0};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
#endif // SECURITY_GUARD_AUTH_COORDINATOR_H
