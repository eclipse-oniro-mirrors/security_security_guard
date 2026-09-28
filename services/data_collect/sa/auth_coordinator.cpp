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
AuthCoordinator::AuthCoordinator() {}

AuthCoordinator::~AuthCoordinator() {}

AuthCoordinator& AuthCoordinator::GetInstance()
{
    static AuthCoordinator instance;
    return instance;
}

// 验收: Provider 接入权限校验
// native token 直接放行；HAP token 校验 ohos.permission.AUTH_SERVICE_ACCESS
int32_t AuthCoordinator::IsProviderAllowed()
{
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        SGLOGI("native token allowed");
        return SUCCESS;
    }
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        int32_t result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken,
            AUTH_SERVICE_ACCESS_PERMISSION);
        if (result == Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
            SGLOGI("HAP token permission granted");
            return SUCCESS;
        }
        SGLOGE("HAP token permission denied");
        return NO_PERMISSION;
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
        return NULL_OBJECT;
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
        return FAILED;
    }
    provider->SetDeathRecipient(recipient);
    providerRemote = provider;
    SGLOGI("create auth provider success, serviceId=%{public}s, pid=%{private}d",
        serviceId.c_str(), static_cast<int32_t>(callerPid));
    NotifyClientStatusChanged();
    return SUCCESS;
}

// 验收: Provider 销毁（幂等，返回 void）
void AuthCoordinator::DestroyAuthProvider(AuthProviderSessionService *provider)
{
    if (provider == nullptr) {
        return;
    }
    SGLOGI("DestroyAuthProvider, serviceId=%{public}s, pid=%{private}d", provider->GetServiceId().c_str(),
        static_cast<int32_t>(provider->GetPid()));
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        auto iter = FindProviderLocked(provider);
        if (iter == providerSessions_.end()) {
            SGLOGE("provider not found");
            return;
        }
        (*iter)->MarkInvalid();
        RemoveProviderLocked(*iter);
    }
    if (provider->GetCallback() != nullptr && provider->GetDeathRecipient() != nullptr) {
        provider->GetCallback()->RemoveDeathRecipient(provider->GetDeathRecipient());
    }
    SGLOGI("destroy auth provider success, pid=%{private}d", static_cast<int32_t>(provider->GetPid()));
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
    NotifyClientStatusChanged();
}

// 降级客户端: 生成 seqnum，用 cJSON 填充 metadata，通知该客户端
void AuthCoordinator::NotifyDegradedClient(int64_t eventId, AuthEventSessionService *session)
{
    int64_t seqnum = ++seqCounter_;
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
    if (proxy != nullptr) {
        proxy->OnAuthEvent(event, seqnum);
    }
}

// 正常客户端: 生成 seqnum + 用 clientId 初始化计数 + 记录映射
void AuthCoordinator::RegisterNormalClient(int64_t eventId, AuthEventSessionService *session,
    RoutingContext &ctx, DispatchResult &result,
    std::vector<std::pair<sptr<IRemoteObject>, AuthStrategy>> &targets)
{
    std::string clientId = session->GetClientId();
    AuthStrategy timeoutStrategy = session->GetTimeoutStrategy();
    ctx.sentClientCount++;
    if (timeoutStrategy == AuthStrategy::DENY) {
        ctx.defaultDenyCount++;
    }
    int64_t seqnum = ++seqCounter_;
    result.seqnums.push_back(seqnum);
    SGLOGD("dispatch, eventId=%{public}" PRId64 ", seqnum=%{public}" PRId64 ", clientId=%{public}s",
        eventId, seqnum, clientId.c_str());
    // clientId → 超时策略 + promise
    {
        std::lock_guard<ffrt::mutex> lk(ctx.ctxMutex);
        ctx.clientTimeoutStrategies[clientId] = timeoutStrategy;
        ctx.clientPromises[clientId] = std::make_shared<std::promise<AuthStrategy>>();
    }
    // seqnum → eventId + session 指针
    {
        std::lock_guard<ffrt::mutex> lk(mutex_);
        seqnumToEventId_[seqnum] = eventId;
        seqnumToSession_[seqnum] = session;
    }
    targets.emplace_back(session->GetCallback(), timeoutStrategy);
}

// 推送 OnAuthEvent: 用 cJSON 填充 AuthEvent.metadata（key=seqNum）
void AuthCoordinator::PushEventsToClients(int64_t eventId,
    const std::vector<std::pair<sptr<IRemoteObject>, AuthStrategy>> &targets,
    const DispatchResult &result)
{
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
        if (proxy != nullptr) {
            proxy->OnAuthEvent(event, seqnum);
        } else {
            SGLOGE("callback proxy is null, seqnum=%{public}" PRId64, seqnum);
        }
    }
}

// 事件路由: 逐个 Client 生成独有 seqnum 并推送 OnAuthEvent
// 降级客户端(isDegraded=true): 从 AuthEventInfo.AuthClientStatus 入参获取，只需通知不参与计数
void AuthCoordinator::DispatchEventToClients(int64_t eventId, int64_t providerUid,
    const std::vector<AuthClientStatus> &clientStatusList,
    RoutingContext &ctx, DispatchResult &result)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    std::vector<std::pair<sptr<IRemoteObject>, AuthStrategy>> targets;
    // 从入参获取降级 clientId 集合
    std::set<std::string> degraderClientIds;
    for (const auto &status : clientStatusList) {
        if (status.IsDegraded()) {
            degraderClientIds.insert(status.GetClientId());
        }
    }
    std::vector<sptr<AuthEventSessionService>> sessions = manager.GetSubscribedSessions(eventId);
    SGLOGI("eventId=%{public}" PRId64 ", subscribed=%{public}zu, degraders=%{public}zu",
        eventId, sessions.size(), degraderClientIds.size());
    for (const auto &session : sessions) {
        if (session == nullptr || !session->IsValid()) {
            continue;
        }
        std::string clientId = session->GetClientId();
        if (degraderClientIds.count(clientId) > 0) {
            SGLOGD("degrader client, notify only, clientId=%{public}s", clientId.c_str());
            NotifyDegradedClient(eventId, session);
            continue;
        }
        RegisterNormalClient(eventId, session, ctx, result, targets);
    }
    SGLOGI("dispatch done, sentClientCount=%{public}zu, defaultDenyCount=%{public}zu",
        ctx.sentClientCount, ctx.defaultDenyCount);
    PushEventsToClients(eventId, targets, result);
}

// 超时处置: 400ms 超时后按各 Client 的 defaultTimeoutStrategy 处理
void AuthCoordinator::HandleTimeout(RoutingContext &ctx)
{
    SGLOGW("eventId=%{public}" PRId64 " timeout, handling pending clients", ctx.eventId);
    for (auto &[clientId, strategy] : ctx.clientTimeoutStrategies) {
        if (ctx.clientResults.find(clientId) != ctx.clientResults.end()) {
            continue;
        }
        ctx.clientResults[clientId] = strategy;
        auto promiseIter = ctx.clientPromises.find(clientId);
        if (promiseIter != ctx.clientPromises.end() && promiseIter->second != nullptr) {
            promiseIter->second->set_value(strategy);
        }
        SGLOGD("timeout, clientId=%{public}s, strategy=%{public}d",
            clientId.c_str(), static_cast<int32_t>(strategy));
        if (strategy == AuthStrategy::DENY) {
            ctx.mergedAuthStrategy = AuthStrategy::DENY;
            ctx.completed = true;
            SGLOGW("timeout DENY triggers block, clientId=%{public}s", clientId.c_str());
        }
    }
    if (!ctx.completed) {
        ctx.mergedAuthStrategy = AuthStrategy::ALLOW;
        ctx.completed = true;
        SGLOGI("all timeout clients ALLOW, mergedAuthStrategy=ALLOW, eventId=%{public}" PRId64, ctx.eventId);
    }
}

// promise/future 等待: 阻塞 ffrt 协程，promise 被写入值后解除阻塞
void AuthCoordinator::WaitForCompletion(RoutingContext &ctx, AuthResult &result,
    int64_t eventId, const std::vector<int64_t> &seqnums)
{
    auto future = ctx.resultPromise->get_future();
    auto status = future.wait_for(std::chrono::milliseconds(AUTH_RESULT_TIMEOUT_MS));
    if (status == std::future_status::timeout) {
        SGLOGW("eventId=%{public}" PRId64 " wait timeout, handling", ctx.eventId);
        HandleTimeout(ctx);
    } else {
        SGLOGI("eventId=%{public}" PRId64 " completed, mergedStrategy=%{public}d",
            ctx.eventId, static_cast<int32_t>(ctx.mergedAuthStrategy));
    }
    BuildAuthResult(ctx, result);
    // 清理: 移除 RoutingContext 和所有 seqnum 映射
    std::lock_guard<ffrt::mutex> lock(mutex_);
    routingContexts_.erase(eventId);
    for (auto s : seqnums) {
        seqnumToEventId_.erase(s);
        seqnumToSession_.erase(s);
    }
    SGLOGD("routing context cleaned, eventId=%{public}" PRId64, eventId);
}

// IPC 异步应答: 返回码承载校验结果（是否接受请求）
// 最终阻断策略经 resultCallback 回调返回（ffrt 异步任务完成后触发）
int32_t AuthCoordinator::RequestAuthResult(AuthProviderSessionService *provider,
    const AuthEventInfo &event, const sptr<IRemoteObject> &resultCallback)
{
    if (provider == nullptr || !provider->IsValid()) {
        SGLOGE("provider is null or invalid");
        return BAD_PARAM;
    }
    int64_t eventId = event.GetEventId();
    SGLOGI("RequestAuthResult, eventId=%{public}" PRId64, eventId);
    // 同步检验并发上限
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        if (routingContexts_.size() >= MAX_AUTH_REQUEST_CONCURRENT) {
            SGLOGE("request auth result exceed concurrent limit, count=%{public}zu",
                routingContexts_.size());
            return AUTH_REQUEST_EXCEED_LIMIT;
        }
    }
    RoutingContext ctx;
    ctx.eventId = eventId;
    ctx.resultPromise = std::make_shared<std::promise<AuthResult>>();
    DispatchResult dispatchResult;
    // 事件路由: 查询订阅 Client → 生成 seqnum → 推送 OnAuthEvent → 初始化双计数
    // 降级客户端从 AuthEventInfo.AuthClientStatus 入参获取
    DispatchEventToClients(eventId, provider->GetUid(), event.GetClientStatus(),
        ctx, dispatchResult);

    // 无订阅 Client → 默认放行，立即回调
    if (ctx.sentClientCount == 0) {
        SGLOGI("no subscribed client, default ALLOW, eventId=%{public}" PRId64, eventId);
        ctx.mergedAuthStrategy = AuthStrategy::ALLOW;
        AuthResult result;
        BuildAuthResult(ctx, result);
        NotifyAuthResult(resultCallback, result);
        return SUCCESS;
    }
    // 注册 RoutingContext（按 eventId 索引，用 unique_ptr 避免不可移动问题）
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        auto ctxPtr = std::make_unique<RoutingContext>();
        ctxPtr->eventId = ctx.eventId;
        ctxPtr->sentClientCount = ctx.sentClientCount;
        ctxPtr->defaultDenyCount = ctx.defaultDenyCount;
        ctxPtr->clientTimeoutStrategies = std::move(ctx.clientTimeoutStrategies);
        ctxPtr->clientPromises = std::move(ctx.clientPromises);
        ctxPtr->resultPromise = std::move(ctx.resultPromise);
        routingContexts_[eventId] = std::move(ctxPtr);
    }
    // ffrt 异步任务: lambda 内通过 eventId 查找 RoutingContext（不捕获裸指针，生命周期由 map 管理）
    ffrt::submit([this, eventId, seqnums = std::move(dispatchResult.seqnums),
                  resultCallback]() {
        RoutingContext *routingCtx = nullptr;
        {
            std::lock_guard<ffrt::mutex> lock(mutex_);
            auto it = routingContexts_.find(eventId);
            if (it == routingContexts_.end() || it->second == nullptr) {
                SGLOGE("routing context not found in ffrt, eventId=%{public}" PRId64, eventId);
                return;
            }
            routingCtx = it->second.get();
        }
        AuthResult result;
        WaitForCompletion(*routingCtx, result, eventId, seqnums);
        NotifyAuthResult(resultCallback, result);
        SGLOGI("async done, eventId=%{public}" PRId64 ", mergedStrategy=%{public}d",
            eventId, static_cast<int32_t>(result.GetMergedAuthStrategy()));
    });
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

// Client 回填: 通过 seqnum 查找 eventId → RoutingContext → 通过 session 获取 clientId → 聚合
int32_t AuthCoordinator::SetAuthResult(AuthEventSessionService *session, const AuthEvent &event,
    int32_t authStrategy, int64_t seqnum)
{
    if (session == nullptr) {
        return BAD_PARAM;
    }
    AuthStrategy strategy = static_cast<AuthStrategy>(authStrategy);
    SGLOGD("SetAuthResult, seqnum=%{public}" PRId64 ", authStrategy=%{public}d",
        seqnum, authStrategy);
    std::lock_guard<ffrt::mutex> lock(mutex_);
    // 通过 seqnum 查找 eventId
    auto eventIdIter = seqnumToEventId_.find(seqnum);
    if (eventIdIter == seqnumToEventId_.end()) {
        SGLOGE("seqnum not found, seqnum=%{public}" PRId64, seqnum);
        return NOT_FOUND;
    }
    int64_t targetEventId = eventIdIter->second;
    // 通过 eventId 查找 RoutingContext
    auto ctxIter = routingContexts_.find(targetEventId);
    if (ctxIter == routingContexts_.end()) {
        SGLOGE("routing context not found, eventId=%{public}" PRId64, targetEventId);
        return NOT_FOUND;
    }
    auto &ctx = *(ctxIter->second);
    std::lock_guard<ffrt::mutex> cvLock(ctx.ctxMutex);
    if (ctx.completed) {
        return SUCCESS;
    }
    // 通过 session 获取 clientId
    std::string clientId = session->GetClientId();
    ctx.clientResults[clientId] = strategy;
    auto promiseIter = ctx.clientPromises.find(clientId);
    if (promiseIter != ctx.clientPromises.end() && promiseIter->second != nullptr) {
        promiseIter->second->set_value(strategy);
    }
    DecrementCounters(ctx, clientId);
    EvaluateStrictPolicy(ctx, strategy, targetEventId);
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

void AuthCoordinator::ReportTimeoutHA(int64_t eventId, int64_t seqnum, int64_t timeoutMs)
{
    SGLOGI("timeout HA report, eventId=%{public}" PRId64 ", seqnum=%{public}" PRId64 ", timeout=%{public}" PRId64,
        eventId, seqnum, timeoutMs);
}

AuthProviderSessionDeathRecipient::AuthProviderSessionDeathRecipient(sptr<AuthProviderSessionService> provider)
    : provider_(std::move(provider))
{
}

void AuthProviderSessionDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    SGLOGI("auth provider died, clean session");
    if (provider_ == nullptr) {
        return;
    }
    AuthCoordinator::GetInstance().RemoveProvider(provider_);
}
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
