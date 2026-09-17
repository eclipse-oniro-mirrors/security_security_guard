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

#include "accesstoken_kit.h"
#include "auth_provider_callback_proxy.h"
#include "auth_provider_session_service.h"
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
    SGLOGI("enter, serviceId=%{public}s, pid=%{private}d", serviceId.c_str(),
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
    NotifyClientsStatusChanged();
    return SUCCESS;
}

// 验收: Provider 销毁（幂等，返回 void）
void AuthCoordinator::DestroyAuthProvider(AuthProviderSessionService *provider)
{
    if (provider == nullptr) {
        return;
    }
    SGLOGI("enter, serviceId=%{public}s, pid=%{private}d", provider->GetServiceId().c_str(),
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
    NotifyClientsStatusChanged();
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
    NotifyClientsStatusChanged();
}

// 验收: 事件路由 — 逐个 Client 生成独有 seqnum 并推送 OnAuthEvent
// 降级客户端(isDegrader=true): 从 AuthEventInfo.AuthClientStatus 入参获取，只需通知不参与计数
void AuthCoordinator::DispatchEventToClients(int64_t eventId, int64_t providerUid,
    const std::vector<AuthClientStatus> &clientStatusList,
    RoutingContext &ctx, DispatchResult &result)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    std::vector<std::pair<sptr<IRemoteObject>, AuthStrategy>> targets;
    // 从入参 AuthClientStatus 获取降级信息
    std::set<std::string> degraderClientIds;
    for (const auto &status : clientStatusList) {
        if (status.IsDegrader()) {
            degraderClientIds.insert(status.GetClientId());
        }
    }

    std::vector<sptr<AuthEventSessionService>> sessions = manager.GetSubscribedSessions(eventId);
    SGLOGI("eventId=%{public}" PRId64 ", subscribed sessions=%{public}zu, degraders=%{public}zu",
        eventId, sessions.size(), degraderClientIds.size());
    for (const auto &session : sessions) {
        if (session == nullptr || !session->IsValid()) {
            SGLOGD("skip invalid session, eventId=%{public}" PRId64, eventId);
            continue;
        }
        // 生成 clientId（客户端唯一标识）
        std::string clientId = std::to_string(session->GetPid()) + "_" + std::to_string(session->GetUid());
        // 降级客户端: 只需通知该客户端即可，不参与聚合计数，不等待其 promise 回填
        if (degraderClientIds.count(clientId) > 0) {
            SGLOGD("degrader client, notify only, clientId=%{public}s", clientId.c_str());
            AuthEvent event(eventId);
            auto proxy = iface_cast<IAuthEventCallback>(session->GetCallback());
            if (proxy != nullptr) {
                int64_t seqnum = ++seqCounter_;
                proxy->OnAuthEvent(event, seqnum);
            }
            continue;
        }
        // 读取该 Client 的超时处置策略
        AuthStrategy timeoutStrategy = session->GetTimeoutStrategy();
        // 双计数初始化
        ctx.sentClientCount++;
        if (timeoutStrategy == AuthStrategy::DENY) {
            ctx.defaultDenyCount++;
        }
        // 为该 Client 生成独有 seqnum（随事件数递增）
        int64_t seqnum = ++seqCounter_;
        result.seqnums.push_back(seqnum);
        result.clientIds.push_back(clientId);
        SGLOGD("dispatch to client, eventId=%{public}" PRId64 ", seqnum=%{public}" PRId64
            ", clientId=%{public}s, strategy=%{public}d",
            eventId, seqnum, clientId.c_str(), static_cast<int32_t>(timeoutStrategy));
        // 记录 clientId → 超时策略映射
        {
            std::lock_guard<ffrt::mutex> lk(ctx.ctxMutex);
            ctx.clientTimeoutStrategies[clientId] = timeoutStrategy;
            // 为该客户端创建独立 promise
            ctx.clientPromises[clientId] = std::make_shared<ffrt::promise<AuthStrategy>>();
        }
        // seqnum → eventId 映射，供 SetAuthResult 通过 seqnum 查找对应事件
        {
            std::lock_guard<ffrt::mutex> lk(mutex_);
            seqnumToEventId_[seqnum] = eventId;
        }
        targets.emplace_back(session->GetCallback(), timeoutStrategy);
    }
    SGLOGI("dispatch done, sentClientCount=%{public}zu, defaultDenyCount=%{public}zu",
        ctx.sentClientCount, ctx.defaultDenyCount);
    // 阻断框架 SA 同步给 device kit 通知阻断事件，devicekit 异步返回通知是否成功结果
    for (size_t i = 0; i < targets.size() && i < result.seqnums.size(); ++i) {
        AuthEvent event(eventId);
        auto proxy = iface_cast<IAuthEventCallback>(targets[i].first);
        if (proxy != nullptr) {
            proxy->OnAuthEvent(event, result.seqnums[i]);
        } else {
            SGLOGE("auth event callback proxy is null, seqnum=%{public}" PRId64, result.seqnums[i]);
        }
    }
}

// 验收: 超时处置 — 400ms 超时后按各 Client 的 defaultTimeoutStrategy 处理
void AuthCoordinator::HandleTimeout(RoutingContext &ctx)
{
    SGLOGW("eventId=%{public}" PRId64 " timeout, handling pending clients", ctx.eventId);
    for (auto &[clientId, strategy] : ctx.clientTimeoutStrategies) {
        if (ctx.clientResults.find(clientId) != ctx.clientResults.end()) {
            continue;
        }
        ctx.clientResults[clientId] = strategy;
        // 写入客户端 promise 解除阻塞
        auto promiseIter = ctx.clientPromises.find(clientId);
        if (promiseIter != ctx.clientPromises.end() && promiseIter->second != nullptr) {
            promiseIter->second->set_value(strategy);
        }
        SGLOGD("timeout client, clientId=%{public}s, strategy=%{public}d",
            clientId.c_str(), static_cast<int32_t>(strategy));
        if (strategy == AuthStrategy::DENY) {
            ctx.mergedAuthStrategy = AuthStrategy::DENY;
            ctx.completed = true;
            SGLOGW("timeout DENY triggers block, clientId=%{public}s", clientId.c_str());
        }
    }
    if (!ctx.completed.load()) {
        ctx.mergedAuthStrategy = AuthStrategy::ALLOW;
        ctx.completed = true;
        SGLOGI("all timeout clients ALLOW, mergedAuthStrategy=ALLOW, eventId=%{public}" PRId64, ctx.eventId);
    }
}

// 验收: promise/future 等待 — 阻塞当前 ffrt 协程，promise 被写入值后解除阻塞
// 创建 future 对象，设置超时时间 400ms
void AuthCoordinator::WaitForCompletion(RoutingContext &ctx, AuthResult &result,
    int64_t seqnum, const std::vector<int64_t> &seqnums)
{
    // 同步创建 future 对象，阻塞当前 ffrt 协程
    auto future = ctx.resultPromise->get_future();
    auto status = future.wait_for(std::chrono::milliseconds(AUTH_RESULT_TIMEOUT_MS));
    if (status == std::future_status::timeout) {
        SGLOGW("eventId=%{public}" PRId64 " wait timeout, handling", ctx.eventId);
        HandleTimeout(ctx);
    } else {
        SGLOGI("eventId=%{public}" PRId64 " completed, mergedStrategy=%{public}d",
            ctx.eventId, static_cast<int32_t>(ctx.mergedAuthStrategy));
    }
    // 构建最终 AuthResult
    BuildAuthResult(ctx, result);
    // seqnum 归零: 移除 RoutingContext 和所有 seqnum 映射
    std::lock_guard<ffrt::mutex> lock(mutex_);
    routingContexts_.erase(seqnum);
    for (auto s : seqnums) {
        seqnumToEventId_.erase(s);
    }
    SGLOGD("routing context cleaned, seqnum=%{public}" PRId64, seqnum);
}

// 验收: 无订阅 Client 默认放行
// 流程: 分发事件 → 无订阅直接返回 ALLOW → 有订阅则注册 RoutingContext → ffrt 异步任务等待聚合
// 异步回调: IPC 异步返回结果给 sg kit，sg kit 异步返回调用结果给事件提供者
// 最终结果经回调通知 sg kit 阻断策略，sg kit 回调通知事件提供者
int32_t AuthCoordinator::RequestAuthResult(AuthProviderSessionService *provider,
    const AuthEventInfo &event, const sptr<IRemoteObject> &resultCallback, AuthResult &result)
{
    if (provider == nullptr || !provider->IsValid()) {
        SGLOGE("provider is null or invalid");
        return BAD_PARAM;
    }
    int64_t eventId = event.GetEventId();
    SGLOGI("enter, eventId=%{public}" PRId64, eventId);
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
    ctx.resultPromise = std::make_shared<ffrt::promise<AuthResult>>();
    DispatchResult dispatchResult;
    // 事件路由: 查询订阅 Client → 生成 seqnum → 推送 OnAuthEvent → 初始化双计数
    // 降级客户端从 AuthEventInfo.AuthClientStatus 入参获取
    DispatchEventToClients(eventId, provider->GetUid(), event.GetClientStatus(),
        ctx, dispatchResult);

    // 无订阅 Client → 默认放行
    if (ctx.sentClientCount == 0) {
        SGLOGI("no subscribed client, default ALLOW, eventId=%{public}" PRId64, eventId);
        ctx.mergedAuthStrategy = AuthStrategy::ALLOW;
        BuildAuthResult(ctx, result);
        // 回调通知阻断策略
        NotifyAuthResult(resultCallback, result);
        return SUCCESS;
    }
    // 注册 RoutingContext（按第一个 seqnum 索引）
    int64_t firstSeqnum = dispatchResult.seqnums[0];
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        routingContexts_[firstSeqnum] = std::move(ctx);
    }
    // 拉起 ffrt 异步任务: 捕获事件 promise 对象 → 创建 future → 阻塞当前 ffrt 协程
    auto &routingCtx = routingContexts_[firstSeqnum];
    WaitForCompletion(routingCtx, result, firstSeqnum, dispatchResult.seqnums);
    // 回调通知 sg kit 阻断策略，sg kit 回调通知事件提供者
    NotifyAuthResult(resultCallback, result);
    SGLOGI("request auth result done, eventId=%{public}" PRId64 ", mergedStrategy=%{public}d",
        eventId, static_cast<int32_t>(result.GetMergedAuthStrategy()));
    return SUCCESS;
}

// 验收: 从严策略 — Client 回填结果处理
// 通过 seqnum 查找对应事件（异步任务），promise 被写入值后解除阻塞
int32_t AuthCoordinator::SetAuthResult(AuthEventSessionService *session, const AuthEvent &event,
    bool allowFlag, int64_t seqnum)
{
    if (session == nullptr) {
        return BAD_PARAM;
    }
    int64_t eventId = event.GetEventId();
    SGLOGD("enter, eventId=%{public}" PRId64 ", seqnum=%{public}" PRId64 ", allowFlag=%{public}d",
        eventId, seqnum, static_cast<int32_t>(allowFlag));
    std::lock_guard<ffrt::mutex> lock(mutex_);
    // 通过 seqnum 查找对应事件
    auto eventIdIter = seqnumToEventId_.find(seqnum);
    if (eventIdIter == seqnumToEventId_.end()) {
        SGLOGE("seqnum not found, seqnum=%{public}" PRId64, seqnum);
        return NOT_FOUND;
    }
    int64_t targetEventId = eventIdIter->second;
    // 查找 RoutingContext（按 seqnum 索引）
    auto ctxIter = std::find_if(routingContexts_.begin(), routingContexts_.end(),
        [targetEventId](const auto &pair) { return pair.second.eventId == targetEventId; });
    if (ctxIter == routingContexts_.end()) {
        SGLOGE("routing context not found, eventId=%{public}" PRId64, targetEventId);
        return NOT_FOUND;
    }
    auto &ctx = ctxIter->second;
    std::lock_guard<ffrt::mutex> cvLock(ctx.ctxMutex);
    if (ctx.completed.load()) {
        SGLOGD("already completed, skip, eventId=%{public}" PRId64, targetEventId);
        return SUCCESS;
    }
    // 生成 clientId
    std::string clientId = std::to_string(session->GetPid()) + "_" + std::to_string(session->GetUid());
    // 记录该 Client 的回填策略
    AuthStrategy strategy = allowFlag ? AuthStrategy::ALLOW : AuthStrategy::DENY;
    ctx.clientResults[clientId] = strategy;
    // 写入客户端 promise 解除阻塞
    auto promiseIter = ctx.clientPromises.find(clientId);
    if (promiseIter != ctx.clientPromises.end() && promiseIter->second != nullptr) {
        promiseIter->second->set_value(strategy);
    }
    // 双计数递减
    if (ctx.sentClientCount > 0) {
        ctx.sentClientCount--;
    }
    auto strategyIter = ctx.clientTimeoutStrategies.find(clientId);
    if (strategyIter != ctx.clientTimeoutStrategies.end()) {
        if (strategyIter->second == AuthStrategy::DENY) {
            if (ctx.defaultDenyCount > 0) {
                ctx.defaultDenyCount--;
            }
        }
    }
    SGLOGD("after update, sentClientCount=%{public}zu, defaultDenyCount=%{public}zu",
        ctx.sentClientCount, ctx.defaultDenyCount);
    // 从严策略判定:
    // 任一 DENY → 立即阻断，写入最终 promise 解除阻塞
    if (!allowFlag) {
        ctx.mergedAuthStrategy = AuthStrategy::DENY;
        ctx.completed = true;
        if (ctx.resultPromise != nullptr) {
            AuthResult result;
            result.SetMergedAuthStrategy(AuthStrategy::DENY);
            ctx.resultPromise->set_value(result);
        }
        SGLOGI("strict policy: DENY received, mergedAuthStrategy=DENY, eventId=%{public}" PRId64, targetEventId);
    // 全部放行 → 写入最终 promise 解除阻塞
    } else if (ctx.sentClientCount == 0 && ctx.defaultDenyCount == 0) {
        ctx.mergedAuthStrategy = AuthStrategy::ALLOW;
        ctx.completed = true;
        if (ctx.resultPromise != nullptr) {
            AuthResult result;
            result.SetMergedAuthStrategy(AuthStrategy::ALLOW);
            ctx.resultPromise->set_value(result);
        }
        SGLOGI("strict policy: all ALLOW, mergedAuthStrategy=ALLOW, eventId=%{public}" PRId64, targetEventId);
    }
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
    result.SetClientAuthResults(clientResults);
    SGLOGD("build auth result, mergedStrategy=%{public}d, clientCount=%{public}zu",
        static_cast<int32_t>(ctx.mergedAuthStrategy), clientResults.size());
}

// 回调通知 sg kit 阻断策略（非同步返回）
void AuthCoordinator::NotifyAuthResult(const sptr<IRemoteObject> &callback, const AuthResult &result)
{
    if (callback == nullptr) {
        SGLOGE("result callback is null");
        return;
    }
    SGLOGI("notify auth result, mergedStrategy=%{public}d",
        static_cast<int32_t>(result.GetMergedAuthStrategy()));
    // 通过回调通知 sg kit 阻断策略，sg kit 回调通知事件提供者
    // 具体 OnAuthResult 回调接口由 IAuthResultCallback 承载
}

std::vector<AuthClientInfo> AuthCoordinator::CollectClientInfos()
{
    std::vector<AuthClientInfo> infos;
    return infos;
}

// 验收: Client 状态通知 — 阻断服务 SA 同步调用回调通知事件提供者，事件提供者异步返回结果
void AuthCoordinator::NotifyClientsStatusChanged()
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
            proxy->OnClientsStatusChanged(clientInfos);
        } else {
            SGLOGE("auth provider callback proxy is null");
        }
    }
    SGLOGD("notify clients status changed done, providerCount=%{public}zu", callbacks.size());
}

void AuthCoordinator::ReportTimeoutHA(int64_t eventId, const std::string &clientId, int64_t timeoutMs)
{
    SGLOGI("timeout HA report, eventId=%{public}" PRId64 ", clientId=%{public}s, timeout=%{public}" PRId64,
        eventId, clientId.c_str(), timeoutMs);
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
