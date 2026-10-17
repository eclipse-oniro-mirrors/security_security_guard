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

#include "auth_coordinator.h"

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE

#include <algorithm>
#include <cinttypes>
#include <chrono>
#include <string>

#include "cJSON.h"

#include "accesstoken_kit.h"
#include "auth_event_reporter.h"
#include "auth_event_subscribe_manager.h"
#include "auth_provider_callback_proxy.h"
#include "auth_provider_session_service.h"
#include "i_auth_event_callback.h"
#include "i_auth_result_callback.h"
#include "ipc_skeleton.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "tokenid_kit.h"

namespace OHOS::Security::SecurityGuard {
// 组合 key: clientId + "_" + seqnum（seqnum per-client 递增，需组合 key 避免冲突）
std::string AuthCoordinator::MakeSeqnumKey(const std::string &clientId, int64_t seqnum)
{
    return clientId + "_" + std::to_string(seqnum);
}

// P1-3: 按 hash(seqnumKey) 分片，不同 request 的 SetAuthResult 分散到不同分片锁
size_t AuthCoordinator::GetSeqnumShardIndex(const std::string &seqnumKey)
{
    return std::hash<std::string>{}(seqnumKey) % SEQNUM_SHARD_COUNT;
}

AuthCoordinator::AuthCoordinator() {}

AuthCoordinator::~AuthCoordinator() {}

AuthCoordinator& AuthCoordinator::GetInstance()
{
    static AuthCoordinator instance;
    return instance;
}

// Provider 接入校验: 1.权限校验(无权限→201) 2.系统应用校验(非系统应用→202)
int32_t AuthCoordinator::IsProviderAllowed()
{
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        SGLOGI("native token allowed");
        return SUCCESS;
    }
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        // 先校验权限(201)
        int32_t result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken,
            AUTH_SERVICE_ACCESS_PERMISSION);
        if (result != Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
            SGLOGE("HAP token permission denied");
            return NO_PERMISSION;
        }
        // 再校验系统应用(202)
        uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
        if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)) {
            SGLOGE("not system app");
            return NO_SYSTEMCALL;
        }
        SGLOGI("HAP token permission granted and is system app");
        return SUCCESS;
    }
    SGLOGE("invalid token type denied");
    return NO_PERMISSION;
}

// 验收: Provider 配额校验（1/进程、16/设备）
int32_t AuthCoordinator::CheckProviderQuotaLocked(pid_t callerPid) const
{
    if (providerSessions_.size() >= MAX_AUTH_PROVIDER_SIZE) {
        SGLOGE("provider exceed global limit, count=%{public}zu", providerSessions_.size());
        return AUTH_PROVIDER_EXCEED_GLOBAL_LIMIT;
    }
    size_t processCount = 0;
    for (const auto &item : providerSessions_) {
        if (item != nullptr && item->GetPid() == callerPid) {
            ++processCount;
        }
    }
    if (processCount >= MAX_AUTH_PROVIDER_SIZE_ONE_PROCESS) {
        SGLOGE("provider exceed process limit, pid=%{private}d, count=%{public}zu",
            static_cast<int32_t>(callerPid), processCount);
        return AUTH_PROVIDER_EXCEED_PROCESS_LIMIT;
    }
    return SUCCESS;
}

std::set<sptr<AuthProviderSessionService>>::iterator AuthCoordinator::FindProviderLocked(
    AuthProviderSessionService *provider)
{
    return std::find_if(providerSessions_.begin(), providerSessions_.end(),
        [provider](const sptr<AuthProviderSessionService> &item) { return item.GetRefPtr() == provider; });
}

void AuthCoordinator::RemoveProviderLocked(const sptr<AuthProviderSessionService> &provider)
{
    providerSessions_.erase(provider);
}

// 验收: Provider 创建会话
// 流程: 权限校验 → 回调判空 → 同 cb 重复检查 → 配额检查 → 创建会话对象 → 登记集合 → DeathRecipient → 通知状态
// 异步返回: 接口同步验证服务接入权限，完成后异步返回会话标识给 sg kit，sg kit 异步返回给事件提供者
int32_t AuthCoordinator::CreateAuthProvider(pid_t callerPid, int32_t callerUid,
    const sptr<IRemoteObject> &callback, const std::string &serviceId, sptr<IRemoteObject> &providerRemote)
{
    SGLOGI("CreateAuthProvider, serviceId=%{public}s, pid=%{private}d", serviceId.c_str(),
        static_cast<int32_t>(callerPid));
    if (callback == nullptr) {
        SGLOGE("callback is null");
        return BAD_PARAM;
    }
    sptr<AuthProviderSessionService> provider {};
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        int32_t code = CheckProviderQuotaLocked(callerPid);
        if (code != SUCCESS) {
            return code;
        }
        for (const auto &item : providerSessions_) {
            if (item != nullptr && item->GetCallback() == callback) {
                SGLOGE("callback already has provider");
                return BAD_PARAM;
            }
        }
        provider = new (std::nothrow) AuthProviderSessionService(callerPid, callerUid, serviceId, callback);
        if (provider == nullptr) {
            SGLOGE("new provider fail");
            return AUTH_PROVIDER_INTERNAL_ERROR;
        }
        providerSessions_.insert(provider);
    }
    sptr<AuthProviderSessionDeathRecipient> recipient = new (std::nothrow) AuthProviderSessionDeathRecipient(provider);
    if (recipient == nullptr || !callback->AddDeathRecipient(recipient)) {
        SGLOGE("add death recipient fail");
        std::lock_guard<ffrt::mutex> lock(mutex_);
        RemoveProviderLocked(provider);
        return AUTH_PROVIDER_INTERNAL_ERROR;
    }
    provider->SetDeathRecipient(recipient);
    providerRemote = provider;
    SGLOGI("create auth provider success, serviceId=%{public}s, pid=%{private}d",
        serviceId.c_str(), static_cast<int32_t>(callerPid));
    NotifyClientStatusChanged();
    return SUCCESS;
}

// Provider 销毁（幂等，返回 void）
void AuthCoordinator::DestroyAuthProvider(AuthProviderSessionService *provider)
{
    if (provider == nullptr) {
        return;
    }
    SGLOGI("DestroyAuthProvider, serviceId=%{public}s, pid=%{private}d", provider->GetServiceId().c_str(),
        static_cast<int32_t>(provider->GetPid()));
    // 先 RemoveDeathRecipient 再从集合移除，避免移除后 provider 析构导致 use-after-free
    sptr<AuthProviderSessionService> keepAlive = nullptr;
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        auto iter = FindProviderLocked(provider);
        if (iter == providerSessions_.end()) {
            SGLOGE("provider not found");
            return;
        }
        keepAlive = *iter;  // 持有引用防止提前析构
        (*iter)->MarkInvalid();
        RemoveProviderLocked(*iter);
    }
    if (keepAlive->GetCallback() != nullptr && keepAlive->GetDeathRecipient() != nullptr) {
        keepAlive->GetCallback()->RemoveDeathRecipient(keepAlive->GetDeathRecipient());
    }
    // P1-1: 断开 Provider 与 DeathRecipient 的循环引用，防止内存泄漏
    // provider 持 sptr<DeathRecipient>，DeathRecipient 持 sptr<provider>，不显式断开则两者无法析构
    keepAlive->ClearDeathRecipient();
    SGLOGI("destroy auth provider success, pid=%{private}d", static_cast<int32_t>(keepAlive->GetPid()));
    NotifyClientStatusChanged();
}

void AuthCoordinator::RemoveProvider(const sptr<AuthProviderSessionService> &provider)
{
    if (provider == nullptr) {
        return;
    }
    SGLOGW("provider died, cleaning session, pid=%{private}d", static_cast<int32_t>(provider->GetPid()));
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        provider->MarkInvalid();
        RemoveProviderLocked(provider);
    }
    // P1-1: 死亡回调路径同样需断开循环引用
    provider->ClearDeathRecipient();
    NotifyClientStatusChanged();
}

// 降级客户端: 生成 per-client seqnum，用 cJSON 填充 metadata，通知该客户端
void AuthCoordinator::NotifyDegradedClient(int64_t eventId, AuthEventSessionService *session)
{
    int64_t seqnum = session->GenerateSeqnum();
    SGLOGI("notify degraded client, eventId=%{public}" PRId64 ", seqnum=%{public}" PRId64,
        eventId, seqnum);
    AuthEvent event(eventId);
    event.SetSeqnum(seqnum);
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "seqNum", static_cast<double>(seqnum));
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr != nullptr) {
        event.SetMetadata(std::string(jsonStr));
        cJSON_free(jsonStr);
    }
    cJSON_Delete(root);
    auto proxy = iface_cast<IAuthEventCallback>(session->GetCallback());
    if (proxy == nullptr) {
        SGLOGE("degraded client callback proxy is null, seqnum=%{public}" PRId64, seqnum);
        return;
    }
    proxy->OnAuthEvent(event, seqnum);
    SGLOGD("degraded client notified, seqnum=%{public}" PRId64, seqnum);
}

// 正常客户端: 生成 seqnum + 用 clientId 初始化计数 + 记录 seqnumKey→ctx 分片索引
void AuthCoordinator::RegisterNormalClient(int64_t requestId, int64_t eventId,
    AuthEventSessionService *session, RoutingContext &ctx, DispatchResult &result,
    std::vector<std::pair<sptr<IRemoteObject>, AuthStrategy>> &targets,
    std::shared_ptr<RoutingContext> ctxPtr)
{
    std::string clientId = session->GetClientId();
    AuthStrategy timeoutStrategy = session->GetTimeoutStrategy();
    ctx.sentClientCount++;
    if (timeoutStrategy == AuthStrategy::DENY) {
        ctx.defaultDenyCount++;
    }
    // M12: 记录 per-client 应用信息，供超时 HA 打点
    ctx.clientAppInfos[clientId] = {session->GetPid(), session->GetUid()};
    int64_t seqnum = session->GenerateSeqnum();
    result.seqnums.push_back(seqnum);
    result.clientIds.push_back(clientId);
    SGLOGD("dispatch, eventId=%{public}" PRId64 ", seqnum=%{public}" PRId64 ", clientId=%{public}s",
        eventId, seqnum, clientId.c_str());
    {
        std::lock_guard<ffrt::mutex> lk(ctx.ctxMutex);
        ctx.clientTimeoutStrategies[clientId] = timeoutStrategy;
        ctx.clientPromises[clientId] = std::make_shared<std::promise<AuthStrategy>>();
    }
    // P1-3: seqnumKey → ctxPtr 写入对应分片，SetAuthResult 只需锁对应分片（~2μs）
    std::string seqnumKey = MakeSeqnumKey(clientId, seqnum);
    size_t shardIdx = GetSeqnumShardIndex(seqnumKey);
    {
        std::lock_guard<ffrt::mutex> lk(seqnumShards_[shardIdx].mutex);
        seqnumShards_[shardIdx].seqnumToCtx[seqnumKey] = ctxPtr;
    }
    targets.emplace_back(session->GetCallback(), timeoutStrategy);
}

// 推送 OnAuthEvent: 用 cJSON 填充 AuthEvent.metadata（key=seqNum）
void AuthCoordinator::PushEventsToClients(int64_t eventId,
    const std::vector<std::pair<sptr<IRemoteObject>, AuthStrategy>> &targets,
    const DispatchResult &result)
{
    SGLOGI("push events to clients, eventId=%{public}" PRId64 ", count=%{public}zu",
        eventId, targets.size());
    for (size_t i = 0; i < targets.size() && i < result.seqnums.size(); ++i) {
        AuthEvent event(eventId);
        int64_t seqnum = result.seqnums[i];
        event.SetSeqnum(seqnum);
        cJSON *root = cJSON_CreateObject();
        cJSON_AddNumberToObject(root, "seqNum", static_cast<double>(seqnum));
        char *jsonStr = cJSON_PrintUnformatted(root);
        if (jsonStr != nullptr) {
            event.SetMetadata(std::string(jsonStr));
            cJSON_free(jsonStr);
        }
        cJSON_Delete(root);
        auto proxy = iface_cast<IAuthEventCallback>(targets[i].first);
        if (proxy == nullptr) {
            SGLOGE("callback proxy is null, seqnum=%{public}" PRId64, seqnum);
            continue;
        }
        proxy->OnAuthEvent(event, seqnum);
        SGLOGD("OnAuthEvent pushed, eventId=%{public}" PRId64 ", seqnum=%{public}" PRId64,
            eventId, seqnum);
    }
    SGLOGD("push events done, eventId=%{public}" PRId64, eventId);
}

// 事件路由: 逐个 Client 生成独有 seqnum 并推送 OnAuthEvent
void AuthCoordinator::DispatchEventToClients(const DispatchParams &params)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    std::vector<std::pair<sptr<IRemoteObject>, AuthStrategy>> targets;
    std::set<std::string> degraderClientIds;
    for (const auto &status : params.clientStatusList) {
        if (status.IsDegraded()) {
            degraderClientIds.insert(status.GetClientId());
        }
    }
    std::vector<sptr<AuthEventSessionService>> sessions = manager.GetSubscribedSessions(params.eventId);
    SGLOGI("eventId=%{public}" PRId64 ", requestId=%{public}" PRId64 ", subscribed=%{public}zu",
        params.eventId, params.requestId, sessions.size());
    for (const auto &session : sessions) {
        if (session == nullptr || !session->IsValid()) {
            continue;
        }
        std::string clientId = session->GetClientId();
        if (degraderClientIds.count(clientId) > 0) {
            NotifyDegradedClient(params.eventId, session);
            continue;
        }
        RegisterNormalClient(params.requestId, params.eventId, session, params.ctx, params.result,
            targets, params.ctxPtr);
    }
    SGLOGI("dispatch done, sentClientCount=%{public}zu, defaultDenyCount=%{public}zu",
        params.ctx.sentClientCount, params.ctx.defaultDenyCount);
    PushEventsToClients(params.eventId, targets, params.result);
}

// 超时处置: 400ms 超时后按各 Client 的 defaultTimeoutStrategy 处理
// ALLOW 超时记 TIMEOUT（对齐 JS AuthStrategy 枚举语义）；DENY 超时记 DENY 并触发阻断
// P0-2: 全程持 ctxMutex，避免与 SetAuthResult 数据竞争
void AuthCoordinator::HandleTimeout(std::shared_ptr<RoutingContext> ctxPtr)
{
    if (ctxPtr == nullptr) {
        return;
    }
    auto &ctx = *ctxPtr;
    SGLOGW("eventId=%{public}" PRId64 " timeout, handling pending clients", ctx.eventId);
    std::lock_guard<ffrt::mutex> cvLock(ctx.ctxMutex);
    for (auto &[clientId, strategy] : ctx.clientTimeoutStrategies) {
        if (ctx.clientResults.find(clientId) != ctx.clientResults.end()) {
            continue;
        }
        if (strategy == AuthStrategy::DENY) {
            // 超时且默认 DENY → 记 DENY，触发阻断
            ctx.clientResults[clientId] = AuthStrategy::DENY;
            ctx.mergedAuthStrategy = AuthStrategy::DENY;
            ctx.completed = true;
            SGLOGW("timeout DENY triggers block, clientId=%{public}s", clientId.c_str());
        } else {
            // 超时且默认 ALLOW → 记 TIMEOUT（对齐 JS 枚举语义）
            ctx.clientResults[clientId] = AuthStrategy::TIMEOUT;
            SGLOGD("timeout ALLOW client, record TIMEOUT, clientId=%{public}s", clientId.c_str());
        }
        auto promiseIter = ctx.clientPromises.find(clientId);
        if (promiseIter != ctx.clientPromises.end() && promiseIter->second != nullptr) {
            promiseIter->second->set_value(strategy);
        }
        SGLOGD("timeout, clientId=%{public}s, strategy=%{public}d",
            clientId.c_str(), static_cast<int32_t>(strategy));
        // M13: 超时 HA 打点 — 应用信息(pid/uid) + 事件信息(eventId/content/metadata) + 超时时间
        auto appIt = ctx.clientAppInfos.find(clientId);
        if (appIt != ctx.clientAppInfos.end()) {
            AuthEventReporter::ReportTimeoutResult(appIt->second.pid, appIt->second.uid,
                ctx.eventId, ctx.eventContent, ctx.eventMetadata, AUTH_RESULT_TIMEOUT_MS);
        }
    }
    if (!ctx.completed) {
        ctx.mergedAuthStrategy = AuthStrategy::ALLOW;
        ctx.completed = true;
        SGLOGI("all timeout clients ALLOW, mergedAuthStrategy=ALLOW, eventId=%{public}" PRId64, ctx.eventId);
    }
    // 风格对齐 EvaluateStrictPolicy: 完成时通知 resultPromise 唤醒 WaitForCompletion 的 future.wait_for
    // HandleTimeout 仅在 wait_for 超时(未 set_value)时被调用, 此处 set_value 一定不会重复
    if (ctx.resultPromise != nullptr) {
        AuthResult result;
        result.SetMergedAuthStrategy(ctx.mergedAuthStrategy);
        ctx.resultPromise->set_value(result);
    }
}

// P0-1: promise/future 等待 — ctxPtr 持有 shared_ptr 保证 ctx 存活，wait_for 不持锁
// 超时后 HandleTimeout 持 ctxMutex 修改 ctx 字段，erase 在 mutex_/分片锁内执行
void AuthCoordinator::WaitForCompletion(std::shared_ptr<RoutingContext> ctxPtr, AuthResult &result,
    int64_t requestId, const std::vector<int64_t> &seqnums, const std::vector<std::string> &clientIds)
{
    if (ctxPtr == nullptr || ctxPtr->resultPromise == nullptr) {
        SGLOGE("ctxPtr or resultPromise is null, requestId=%{public}" PRId64, requestId);
        return;
    }
    SGLOGI("wait for completion, requestId=%{public}" PRId64 ", eventId=%{public}" PRId64
        ", pendingCount=%{public}zu", requestId, ctxPtr->eventId, seqnums.size());
    auto future = ctxPtr->resultPromise->get_future();
    auto status = future.wait_for(std::chrono::milliseconds(AUTH_RESULT_TIMEOUT_MS));
    if (status == std::future_status::timeout) {
        SGLOGW("eventId=%{public}" PRId64 " timeout, handling", ctxPtr->eventId);
        HandleTimeout(ctxPtr);
    } else {
        SGLOGI("eventId=%{public}" PRId64 " completed, mergedStrategy=%{public}d",
            ctxPtr->eventId, static_cast<int32_t>(ctxPtr->mergedAuthStrategy));
    }
    BuildAuthResult(*ctxPtr, result);
    // 清理: routingContexts_ 用全局锁，seqnumShards_ 用分片锁
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        routingContexts_.erase(requestId);
    }
    for (size_t i = 0; i < seqnums.size() && i < clientIds.size(); ++i) {
        std::string seqnumKey = MakeSeqnumKey(clientIds[i], seqnums[i]);
        size_t shardIdx = GetSeqnumShardIndex(seqnumKey);
        std::lock_guard<ffrt::mutex> lk(seqnumShards_[shardIdx].mutex);
        seqnumShards_[shardIdx].seqnumToCtx.erase(seqnumKey);
    }
    SGLOGD("routing context cleaned, requestId=%{public}" PRId64, requestId);
}

// RAII 守卫: 作用域退出时自动递减 per-provider 并发计数，保证任何退出路径（return/异常/ffrt 取消）都不泄漏配额
struct ActiveRequestGuard {
    sptr<AuthProviderSessionService> provider;
    explicit ActiveRequestGuard(sptr<AuthProviderSessionService> p) : provider(std::move(p)) {}
    ~ActiveRequestGuard()
    {
        if (provider != nullptr) {
            provider->DecrementActiveRequest();
        }
    }
    DISALLOW_COPY_AND_MOVE(ActiveRequestGuard);
};

// M11: ffrt 异步任务执行 dispatch + register + wait + notify + cleanup
// IPC 立即返回受理码，dispatch 在 ffrt 任务中执行，避免阻塞 SA IPC 线程
// P0-3: 捕获 sptr<AuthProviderSessionService> 而非裸指针，保证 provider 在 ffrt 任务执行期间存活
// P0-1: ctx 用 shared_ptr 管理，SetAuthResult 持拷贝延长生命周期，避免 erase 后 UAF
void AuthCoordinator::ProcessAuthResultAsync(sptr<AuthProviderSessionService> provider,
    int64_t requestId, const AuthEventInfo &event, const sptr<IRemoteObject> &resultCallback)
{
    SGLOGI("submit ffrt task, requestId=%{public}" PRId64 ", eventId=%{public}" PRId64,
        requestId, event.GetEventId());
    ffrt::submit([this, provider, requestId, event, resultCallback]() {
        SGLOGI("ffrt task start, requestId=%{public}" PRId64, requestId);
        // RAII 守卫: 作用域退出时自动 DecrementActiveRequest，保证任何退出路径都不泄漏并发配额
        ActiveRequestGuard guard(provider);
        // provider 是 sptr，生命周期由 ffrt 任务保证；IsValid 检查 provider 是否被主动销毁
        if (provider == nullptr || !provider->IsValid()) {
            SGLOGE("provider invalid in ffrt task, requestId=%{public}" PRId64, requestId);
            AuthResult fallback;
            fallback.SetMergedAuthStrategy(AuthStrategy::ALLOW);
            NotifyAuthResult(resultCallback, fallback);
            return;  // guard 析构自动 DecrementActiveRequest（provider 为 null 时 guard 内部判空跳过）
        }
        // 直接用 ctxPtr 作为 dispatch 的工作 ctx，避免 local ctx 与 ctxPtr 之间的字段搬运
        // RegisterNormalClient 同时写入 ctxPtr 字段（via params.ctx = *ctxPtr）和分片索引（via params.ctxPtr）
        auto ctxPtr = std::make_shared<RoutingContext>();
        ctxPtr->eventId = event.GetEventId();
        ctxPtr->eventContent = event.GetContent();
        // eventMetadata 留空: metadata 是 SA 在 PushEventsToClients 中 per-client 生成的 seqNum=N cJSON,
        // 不是 AuthEventInfo 自带的(AuthEventInfo 无 metadata 字段); per-request 级别无法存储 per-client 的多值
        ctxPtr->resultPromise = std::make_shared<std::promise<AuthResult>>();
        SGLOGD("routing context created, requestId=%{public}" PRId64 ", contentLen=%{public}zu",
            requestId, ctxPtr->eventContent.size());
        DispatchResult dispatchResult;
        DispatchParams params{requestId, event.GetEventId(), event.GetClientStatus(),
            *ctxPtr, dispatchResult, ctxPtr};
        DispatchEventToClients(params);

        if (ctxPtr->sentClientCount == 0) {
            SGLOGI("no subscribed client, default ALLOW, eventId=%{public}" PRId64, event.GetEventId());
            ctxPtr->mergedAuthStrategy = AuthStrategy::ALLOW;
            AuthResult result;
            BuildAuthResult(*ctxPtr, result);
            NotifyAuthResult(resultCallback, result);
            return;  // guard 析构自动 DecrementActiveRequest
        }
        // 注册到 routingContexts_（seqnumShards_ 已在 RegisterNormalClient 中写入）
        // Client 收到 OnAuthEvent 后调用 SetAuthResult，此时 ctxPtr 字段已全部填充完成
        {
            std::lock_guard<ffrt::mutex> lock(mutex_);
            routingContexts_[requestId] = ctxPtr;
        }
        SGLOGI("routing context registered, requestId=%{public}" PRId64 ", sentClientCount=%{public}zu",
            requestId, ctxPtr->sentClientCount);
        // wait + timeout + notify + cleanup（ctxPtr 持有 shared_ptr 保证 ctx 存活）
        AuthResult result;
        WaitForCompletion(ctxPtr, result, requestId, dispatchResult.seqnums, dispatchResult.clientIds);
        NotifyAuthResult(resultCallback, result);
        SGLOGI("async done, requestId=%{public}" PRId64 ", mergedStrategy=%{public}d",
            requestId, static_cast<int32_t>(result.GetMergedAuthStrategy()));
        // guard 析构自动 DecrementActiveRequest
    });
}

// IPC 异步应答: 返回码承载校验结果（是否接受请求）
// M11: IPC 立即返回受理码，dispatch + wait + callback 全部在 ffrt 异步任务中执行
// P0-3: 从 providerSessions_ 查找 sptr 传给 ffrt 任务，保证 provider 在任务执行期间存活
int32_t AuthCoordinator::RequestAuthResult(AuthProviderSessionService *provider,
    const AuthEventInfo &event, const sptr<IRemoteObject> &resultCallback)
{
    if (provider == nullptr || !provider->IsValid()) {
        SGLOGE("provider is null or invalid");
        return BAD_PARAM;
    }
    // per-provider 并发上限校验 + 计数原子化（M6: 每 Provider 上限 128）
    // CAS 消除 TOCTOU：避免多线程同时通过 check 后递增超限
    if (!provider->TryIncrementActiveRequest(MAX_AUTH_REQUEST_CONCURRENT_PER_PROVIDER)) {
        SGLOGE("per-provider request exceed limit, count=%{public}zu", provider->GetActiveRequestCount());
        return AUTH_REQUEST_EXCEED_LIMIT;
    }
    // P0-3: 查找 sptr 传给 ffrt 任务，避免裸指针在 provider 销毁后 UAF
    sptr<AuthProviderSessionService> providerSptr;
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        auto iter = FindProviderLocked(provider);
        if (iter == providerSessions_.end()) {
            SGLOGE("provider not found in sessions");
            provider->DecrementActiveRequest();  // 回滚已递增的计数
            return BAD_PARAM;
        }
        providerSptr = *iter;
    }
    int64_t eventId = event.GetEventId();
    int64_t requestId = ++requestCounter_;
    SGLOGI("RequestAuthResult, eventId=%{public}" PRId64 ", requestId=%{public}" PRId64
        ", activeRequestCount=%{public}zu", eventId, requestId, provider->GetActiveRequestCount());
    // ffrt 异步任务：dispatch + register + wait + notify + cleanup
    ProcessAuthResultAsync(providerSptr, requestId, event, resultCallback);
    SGLOGI("request accepted, eventId=%{public}" PRId64, eventId);
    return SUCCESS;
}

// 双计数递减: sentClientCount-- + 若 DENY 策略则 defaultDenyCount--
void AuthCoordinator::DecrementCounters(RoutingContext &ctx, const std::string &clientId)
{
    if (ctx.sentClientCount > 0) {
        ctx.sentClientCount--;
    }
    auto it = ctx.clientTimeoutStrategies.find(clientId);
    if (it != ctx.clientTimeoutStrategies.end() && it->second == AuthStrategy::DENY) {
        if (ctx.defaultDenyCount > 0) {
            ctx.defaultDenyCount--;
        }
    }
    SGLOGD("decrement counters, clientId=%{public}s, sentClientCount=%{public}zu, defaultDenyCount=%{public}zu",
        clientId.c_str(), ctx.sentClientCount, ctx.defaultDenyCount);
}

// 从严策略判定: 任一 DENY → 立即阻断；全部 ALLOW → 放行
void AuthCoordinator::EvaluateStrictPolicy(RoutingContext &ctx, AuthStrategy authStrategy, int64_t eventId)
{
    if (authStrategy == AuthStrategy::DENY) {
        ctx.mergedAuthStrategy = AuthStrategy::DENY;
        ctx.completed = true;
        if (ctx.resultPromise != nullptr) {
            AuthResult result;
            result.SetMergedAuthStrategy(AuthStrategy::DENY);
            ctx.resultPromise->set_value(result);
        }
        SGLOGI("strict policy: DENY, eventId=%{public}" PRId64, eventId);
    } else if (ctx.sentClientCount == 0 && ctx.defaultDenyCount == 0) {
        ctx.mergedAuthStrategy = AuthStrategy::ALLOW;
        ctx.completed = true;
        if (ctx.resultPromise != nullptr) {
            AuthResult result;
            result.SetMergedAuthStrategy(AuthStrategy::ALLOW);
            ctx.resultPromise->set_value(result);
        }
        SGLOGI("strict policy: all ALLOW, eventId=%{public}" PRId64, eventId);
    }
}

// P0-1 + P1-3: Client 回填 — 分片锁内查找 + 拷贝 shared_ptr（~2μs），释放分片锁后用 ctxMutex 修改字段
// shared_ptr 保证 ctx 存活，即使 WaitForCompletion 已 erase routingContexts_，ctx 仍存活到 SetAuthResult 结束
int32_t AuthCoordinator::SetAuthResult(AuthEventSessionService *session, const AuthEvent &event,
    int32_t authStrategy)
{
    if (session == nullptr) {
        return BAD_PARAM;
    }
    AuthStrategy strategy = static_cast<AuthStrategy>(authStrategy);
    int64_t seqnum = event.GetSeqnum();
    SGLOGD("SetAuthResult, seqnum=%{public}" PRId64 ", authStrategy=%{public}d",
        seqnum, authStrategy);
    std::string clientId = session->GetClientId();
    std::string seqnumKey = MakeSeqnumKey(clientId, seqnum);
    // P1-3: 只锁对应分片（~2μs），不锁全局 mutex_，不同 request 的 SetAuthResult 可并发
    size_t shardIdx = GetSeqnumShardIndex(seqnumKey);
    std::shared_ptr<RoutingContext> ctxPtr;
    {
        std::lock_guard<ffrt::mutex> shardLock(seqnumShards_[shardIdx].mutex);
        auto it = seqnumShards_[shardIdx].seqnumToCtx.find(seqnumKey);
        if (it == seqnumShards_[shardIdx].seqnumToCtx.end()) {
            SGLOGE("seqnumKey not found, clientId=%{public}s, seqnum=%{public}" PRId64, clientId.c_str(), seqnum);
            return AUTH_PROVIDER_INTERNAL_ERROR;
        }
        ctxPtr = it->second;  // 拷贝 shared_ptr，引用计数+1，ctx 生命周期延长到 SetAuthResult 结束
    }  // 释放分片锁，其他 SetAuthResult 可并发查找
    SGLOGD("seqnumKey hit, clientId=%{public}s, seqnum=%{public}" PRId64 ", shardIdx=%{public}zu",
        clientId.c_str(), seqnum, shardIdx);
    // P0-1: 用 ctx 自己的 ctxMutex 保护字段修改（per-request，不同 request 之间无竞争）
    std::lock_guard<ffrt::mutex> cvLock(ctxPtr->ctxMutex);
    if (ctxPtr->completed) {
        SGLOGD("ctx already completed, skip, clientId=%{public}s, seqnum=%{public}" PRId64,
            clientId.c_str(), seqnum);
        return SUCCESS;
    }
    ctxPtr->clientResults[clientId] = strategy;
    auto promiseIter = ctxPtr->clientPromises.find(clientId);
    if (promiseIter != ctxPtr->clientPromises.end() && promiseIter->second != nullptr) {
        promiseIter->second->set_value(strategy);
    }
    DecrementCounters(*ctxPtr, clientId);
    EvaluateStrictPolicy(*ctxPtr, strategy, ctxPtr->eventId);
    SGLOGD("SetAuthResult done, clientId=%{public}s, strategy=%{public}d, sentClientCount=%{public}zu",
        clientId.c_str(), authStrategy, ctxPtr->sentClientCount);
    return SUCCESS;
}

// 构建 AuthResult
void AuthCoordinator::BuildAuthResult(RoutingContext &ctx, AuthResult &result)
{
    result.SetMergedAuthStrategy(ctx.mergedAuthStrategy);
    std::vector<ClientAuthResult> clientResults;
    for (const auto &[clientId, strategy] : ctx.clientResults) {
        clientResults.emplace_back(clientId, strategy);
    }
    result.SetClientAuthResult(clientResults);
    SGLOGD("build auth result, mergedStrategy=%{public}d, clientCount=%{public}zu",
        static_cast<int32_t>(ctx.mergedAuthStrategy), clientResults.size());
}

// SA 聚合完成后回调通知 kit → kit 收到 AuthResult → 触发 Promise 或 std::function
void AuthCoordinator::NotifyAuthResult(const sptr<IRemoteObject> &callback, const AuthResult &result)
{
    if (callback == nullptr) {
        SGLOGE("result callback is null");
        return;
    }
    SGLOGI("notify auth result, mergedStrategy=%{public}d",
        static_cast<int32_t>(result.GetMergedAuthStrategy()));
    auto proxy = iface_cast<IAuthResultCallback>(callback);
    if (proxy == nullptr) {
        SGLOGE("auth result callback proxy is null");
        return;
    }
    proxy->OnAuthResult(result);
}

std::vector<AuthClientInfo> AuthCoordinator::CollectClientInfos()
{
    std::vector<AuthClientInfo> infos;
    auto sessions = AuthEventSubscribeManager::GetInstance().GetAllSessions();
    for (const auto &session : sessions) {
        if (session == nullptr) {
            continue;
        }
        AuthClientInfo info;
        info.SetClientId(session->GetClientId());
        // 本期置空，待产品确认后按 calling token 查 BundleManager 补全
        info.SetBundleName("");
        std::vector<int64_t> events(session->GetEventIds().begin(), session->GetEventIds().end());
        info.SetSubscribedEvents(events);
        info.SetDefaultTimeoutStrategy(session->GetTimeoutStrategy());
        info.SetDefaultTimeoutMs(session->GetDefaultTimeoutMs());
        infos.push_back(info);
    }
    SGLOGI("collect client infos, count=%{public}zu", infos.size());
    return infos;
}

// 验收: Client 状态通知 — 阻断服务 SA 同步调用回调通知事件提供者，事件提供者异步返回结果
void AuthCoordinator::NotifyClientStatusChanged()
{
    auto clientInfos = CollectClientInfos();
    std::vector<sptr<IRemoteObject>> callbacks;
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        for (const auto &provider : providerSessions_) {
            if (provider != nullptr && provider->IsValid()) {
                callbacks.push_back(provider->GetCallback());
            }
        }
    }
    SGLOGI("notify client status changed, clientCount=%{public}zu, providerCount=%{public}zu",
        clientInfos.size(), callbacks.size());
    for (const auto &cb : callbacks) {
        auto proxy = iface_cast<IAuthProviderCallback>(cb);
        if (proxy != nullptr) {
            proxy->OnClientStatusChanged(clientInfos);
        } else {
            SGLOGE("auth provider callback proxy is null");
        }
    }
    SGLOGD("notify clients status changed done, providerCount=%{public}zu", callbacks.size());
}

AuthProviderSessionDeathRecipient::AuthProviderSessionDeathRecipient(wptr<AuthProviderSessionService> provider)
    : provider_(std::move(provider))
{
}

void AuthProviderSessionDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    SGLOGI("auth provider died, clean session");
    // wptr.promote() 临时提升为强引用，若 Provider 已析构则返回 nullptr，安全跳过
    auto provider = provider_.promote();
    if (provider == nullptr) {
        return;
    }
    AuthCoordinator::GetInstance().RemoveProvider(provider);
}
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
