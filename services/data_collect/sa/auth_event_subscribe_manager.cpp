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

#include "auth_event_subscribe_manager.h"

#include <algorithm>
#include <cinttypes>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"

#include "auth_event_callback_proxy.h"
#include "auth_event_reporter.h"
#include "auth_coordinator.h"
#include "i_auth_event_callback.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
namespace OHOS::Security::SecurityGuard {

AuthEventSubscribeManager& AuthEventSubscribeManager::GetInstance()
{
    static AuthEventSubscribeManager instance;
    return instance;
}

AuthEventSubscribeManager::AuthEventSubscribeManager()
{
    // 允许接入的 native token uid 白名单：具体值待产品确认后补入；
    // 空清单表示暂拒所有 native token 接入，补值后即生效。
    allowedUids_ = {};
}

AuthEventSubscribeManager::~AuthEventSubscribeManager() = default;

bool AuthEventSubscribeManager::IsUidAllowed(int32_t uid) const
{
    return std::find(allowedUids_.begin(), allowedUids_.end(), uid) != allowedUids_.end();
}

int32_t AuthEventSubscribeManager::IsCallerAllowed()
{
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        int32_t callingUid = static_cast<int32_t>(IPCSkeleton::GetCallingUid());
        if (!GetInstance().IsUidAllowed(callingUid)) {
            SGLOGE("native caller uid not allowed");
            return NO_PERMISSION;
        }
        return SUCCESS;
    }
    if (tokenType == AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        int code = AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, AUTH_AUDIT_EVENT_PERMISSION);
        if (code == AccessToken::PermissionState::PERMISSION_GRANTED) {
            return SUCCESS;
        }
        SGLOGE("hap caller verify access token denied");
        return NO_PERMISSION;
    }
    SGLOGE("token type not allowed");
    return NO_PERMISSION;
}

int32_t AuthEventSubscribeManager::CheckQuotaLocked(pid_t callerPid) const
{
    if (sessions_.size() >= MAX_AUTH_EVENT_CLIENT_SIZE) {
        SGLOGE("max client size limited");
        return CLIENT_EXCEED_GLOBAL_LIMIT;
    }
    size_t pidClientCount = 0;
    for (const auto &session : sessions_) {
        if (session != nullptr && session->GetPid() == callerPid) {
            ++pidClientCount;
        }
    }
    if (pidClientCount >= MAX_AUTH_EVENT_CLIENT_SIZE_ONE_PROCESS) {
        SGLOGE("max client size one process limited");
        return CLIENT_EXCEED_PROCESS_LIMIT;
    }
    return SUCCESS;
}

std::set<sptr<AuthEventSessionService>>::iterator AuthEventSubscribeManager::FindSessionLocked(
    AuthEventSessionService *session)
{
    return std::find_if(sessions_.begin(), sessions_.end(),
        [session](const sptr<AuthEventSessionService> &item) { return item.GetRefPtr() == session; });
}

void AuthEventSubscribeManager::RemoveSessionLocked(const sptr<AuthEventSessionService> &session)
{
    auto iter = sessions_.find(session);
    if (iter != sessions_.end()) {
        (*iter)->MarkInvalid();
        sessions_.erase(iter);
    }
}

int32_t AuthEventSubscribeManager::CreatAuthEventClient(const CreateClientParams &params,
    sptr<IRemoteObject> &sessionRemote)
{
    if (params.callback == nullptr) {
        SGLOGE("callback is null");
        return NULL_OBJECT;
    }
    sptr<AuthEventSessionService> session {};
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        int32_t code = CheckQuotaLocked(params.callerPid);
        if (code != SUCCESS) {
            return code;
        }
        for (const auto &item : sessions_) {
            if (item != nullptr && item->GetCallback() == params.callback) {
                SGLOGE("callback already has session");
                return BAD_PARAM;
            }
        }
        AuthStrategy strategy = params.timeoutAllowFlag ? AuthStrategy::ALLOW : AuthStrategy::DENY;
        session = new (std::nothrow) AuthEventSessionService(params.callerPid, params.callerUid,
            strategy, params.defaultTimeoutMs, params.callback);
        if (session == nullptr) {
            SGLOGE("new session fail");
            return FAILED;
        }
        sessions_.insert(session);
    }
    // AddDeathRecipient 是跨进程调用，放锁外执行；失败则回滚会话，避免孤儿会话占用配额
    sptr<AuthEventSessionDeathRecipient> recipient = new (std::nothrow) AuthEventSessionDeathRecipient(session);
    if (recipient == nullptr || !params.callback->AddDeathRecipient(recipient)) {
        SGLOGE("add death recipient fail");
        std::lock_guard<ffrt::mutex> lock(mutex_);
        RemoveSessionLocked(session);
        return FAILED;
    }
    session->SetDeathRecipient(recipient);
    sessionRemote = session;
    SGLOGI("create auth event client, pid=%{public}d", static_cast<int32_t>(params.callerPid));
    return SUCCESS;
}

int32_t AuthEventSubscribeManager::SubscribeAuthEvent(AuthEventSessionService *session, int64_t eventId)
{
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        auto iter = FindSessionLocked(session);
        if (iter == sessions_.end()) {
            SGLOGE("session not found");
            return BAD_PARAM;
        }
        auto &eventIds = (*iter)->GetEventIds();
        if (eventIds.size() >= MAX_AUTH_EVENT_SUBSCRIBE_SIZE) {
            SGLOGE("subscribe size limited");
            return FILTER_EXCEED_LIMIT;
        }
        eventIds.insert(eventId);
    }
    // 异步通知 Provider 刷新客户端列表
    ffrt::submit([]() { AuthCoordinator::GetInstance().NotifyClientStatusChanged(); });
    SGLOGI("subscribe auth event, eventId=%{public}" PRId64, eventId);
    return SUCCESS;
}

int32_t AuthEventSubscribeManager::UnsubscribeAuthEvent(AuthEventSessionService *session, int64_t eventId)
{
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        auto iter = FindSessionLocked(session);
        if (iter == sessions_.end()) {
            SGLOGE("session not found");
            return BAD_PARAM;
        }
        (*iter)->GetEventIds().erase(eventId);
    }
    // 异步通知 Provider 刷新客户端列表
    ffrt::submit([]() { AuthCoordinator::GetInstance().NotifyClientStatusChanged(); });
    SGLOGI("unsubscribe auth event, eventId=%{public}" PRId64, eventId);
    return SUCCESS;
}

// 验收: Client 扩展参数 — defaultTimeoutStrategy 保存到会话，供协调者超时处置时读取
// 锁内存表，锁外转发到 Coordinator，驱动从严聚合与 promise 解阻塞（避免嵌套持锁）
int32_t AuthEventSubscribeManager::SetAuthResult(AuthEventSessionService *session, const AuthEvent &event,
    int32_t authStrategy)
{
    AuthStrategy strategy = static_cast<AuthStrategy>(authStrategy);
    if (event.GetContent().size() > MAX_AUTH_EVENT_STR_LEN || event.GetMetadata().size() > MAX_AUTH_EVENT_STR_LEN) {
        SGLOGE("content or metadata too long");
        return BAD_PARAM;
    }
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        auto iter = FindSessionLocked(session);
        if (iter == sessions_.end()) {
            SGLOGE("session not found");
            return BAD_PARAM;
        }
        if (authResults_.find(event.GetEventId()) == authResults_.end() &&
            authResults_.size() >= MAX_AUTH_EVENT_RESULT_SIZE) {
            SGLOGE("auth result size limited");
            return FILTER_EXCEED_LIMIT;
        }
        authResults_[event.GetEventId()] = strategy;
    }
    // 锁外转发到 Coordinator，驱动从严聚合与 promise 解阻塞
    AuthCoordinator::GetInstance().SetAuthResult(session, event, authStrategy);
    if (strategy == AuthStrategy::DENY) {
        AuthEventReporter::ReportAuthBlockResult(session->GetPid(), session->GetUid(), event);
    }
    SGLOGI("set auth result, eventId=%{public}" PRId64 ", authStrategy=%{public}d", event.GetEventId(), authStrategy);
    return SUCCESS;
}

int32_t AuthEventSubscribeManager::GetAuthResult(int64_t eventId, AuthStrategy &authStrategy)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    auto iter = authResults_.find(eventId);
    if (iter == authResults_.end()) {
        return NOT_FOUND;
    }
    authStrategy = iter->second;
    return SUCCESS;
}

int32_t AuthEventSubscribeManager::DestroyAuthEventClient(AuthEventSessionService *session)
{
    if (session == nullptr) {
        return BAD_PARAM;
    }
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        RemoveSessionLocked(session);
    }
    // RemoveDeathRecipient 是跨进程调用，放锁外执行；重复 Destroy 幂等返回 SUCCESS
    sptr<IRemoteObject> callback = session->GetCallback();
    sptr<IRemoteObject::DeathRecipient> recipient = session->GetDeathRecipient();
    if (callback != nullptr && recipient != nullptr) {
        callback->RemoveDeathRecipient(recipient);
    }
    // 异步通知 Provider 刷新客户端列表
    ffrt::submit([]() { AuthCoordinator::GetInstance().NotifyClientStatusChanged(); });
    SGLOGI("destroy auth event client");
    return SUCCESS;
}

void AuthEventSubscribeManager::RemoveSession(const sptr<AuthEventSessionService> &session)
{
    if (session == nullptr) {
        return;
    }
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        RemoveSessionLocked(session);
    }
    // RemoveDeathRecipient 是跨进程调用，放锁外执行
    sptr<IRemoteObject> callback = session->GetCallback();
    sptr<IRemoteObject::DeathRecipient> recipient = session->GetDeathRecipient();
    if (callback != nullptr && recipient != nullptr) {
        callback->RemoveDeathRecipient(recipient);
    }
    // 异步通知 Provider 刷新客户端列表
    ffrt::submit([]() { AuthCoordinator::GetInstance().NotifyClientStatusChanged(); });
}

void AuthEventSubscribeManager::NotifyAuthEvent(const AuthEvent &event)
{
    if (event.GetContent().size() > MAX_AUTH_EVENT_STR_LEN || event.GetMetadata().size() > MAX_AUTH_EVENT_STR_LEN) {
        SGLOGE("content or metadata too long, discard event");
        return;
    }
    // 锁内快照命中会话的回调，锁外执行推送，避免持锁跨进程调用
    std::vector<sptr<IRemoteObject>> callbacks {};
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        for (const auto &session : sessions_) {
            if (session == nullptr || session->GetCallback() == nullptr) {
                continue;
            }
            if (!session->IsEventSubscribed(event.GetEventId())) {
                continue;
            }
            callbacks.push_back(session->GetCallback());
        }
    }
    for (const auto &callback : callbacks) {
        auto proxy = iface_cast<IAuthEventCallback>(callback);
        if (proxy == nullptr) {
            SGLOGE("auth event callback proxy is null");
            continue;
        }
        proxy->OnAuthEvent(event, 0);
    }
}

// 供 AuthCoordinator 调用: 查询订阅了指定 eventId 的所有有效 Client 会话
std::vector<sptr<AuthEventSessionService>> AuthEventSubscribeManager::GetSubscribedSessions(int64_t eventId)
{
    std::vector<sptr<AuthEventSessionService>> result;
    std::lock_guard<ffrt::mutex> lock(mutex_);
    for (const auto &session : sessions_) {
        if (session == nullptr || !session->IsValid()) {
            continue;
        }
        if (session->IsEventSubscribed(eventId)) {
            result.push_back(session);
        }
    }
    return result;
}

// 供 AuthCoordinator 收集全量 Client 信息（锁内快照，锁外由调用方使用）
std::vector<sptr<AuthEventSessionService>> AuthEventSubscribeManager::GetAllSessions()
{
    std::vector<sptr<AuthEventSessionService>> result;
    std::lock_guard<ffrt::mutex> lock(mutex_);
    for (const auto &session : sessions_) {
        if (session != nullptr && session->IsValid()) {
            result.push_back(session);
        }
    }
    return result;
}
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
