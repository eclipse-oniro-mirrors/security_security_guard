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

#include "auth_event_session_service.h"

#include <cinttypes>
#include <chrono>
#include <string>

#include "ipc_skeleton.h"
#ifdef HICOLLIE_ENABLE
#include "xcollie/xcollie_define.h"
#endif
#include "xcollie_utils.h"

#include "auth_event_subscribe_manager.h"
#include "config_data_manager.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
namespace OHOS::Security::SecurityGuard {
namespace {
#ifdef HICOLLIE_ENABLE
constexpr uint32_t XCOLLIE_FLAG = OHOS::HiviewDFX::XCOLLIE_FLAG_LOG | OHOS::HiviewDFX::XCOLLIE_FLAG_RECOVERY;
#else
constexpr uint32_t XCOLLIE_FLAG = 0;
#endif
}

AuthEventSessionService::AuthEventSessionService(pid_t callerPid, int32_t callerUid,
    AuthStrategy defaultTimeoutStrategy, int32_t defaultTimeoutMs, const sptr<IRemoteObject> &callback)
    : pid_(callerPid), uid_(callerUid), defaultTimeoutStrategy_(defaultTimeoutStrategy),
      defaultTimeoutMs_(defaultTimeoutMs), callback_(callback)
{
    // 按 ConstructClientId 范式生成 clientId（时间戳 + 指针 hash）
    std::string timeStr = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    std::string ptrStr = std::to_string(reinterpret_cast<int64_t>(callback.GetRefPtr()));
    clientId_ = std::to_string(std::hash<std::string>{}(timeStr + ptrStr));
}

ErrCode AuthEventSessionService::Subscribe(int64_t eventId)
{
    SGLOGI("eventId=%{public}" PRId64, eventId);
    int32_t code = AuthEventSubscribeManager::GetInstance().IsCallerAllowed();
    if (code != SUCCESS) {
        return code;
    }
    if (!IsValid()) {
        SGLOGE("session is invalid");
        return BAD_PARAM;
    }
    if (IPCSkeleton::GetCallingPid() != pid_) {
        SGLOGE("session not belong to caller");
        return BAD_PARAM;
    }
    XCollie_Utils xcollie("SGIPC_AuthSessionSubscribe", XCOLLIE_FLAG);
    EventCfg config {};
    if (!ConfigDataManager::GetInstance().GetEventConfig(eventId, config)) {
        SGLOGE("GetEventConfig error, eventId is 0x%{public}" PRIx64, eventId);
        return BAD_PARAM;
    }
    return AuthEventSubscribeManager::GetInstance().SubscribeAuthEvent(this, eventId);
}

ErrCode AuthEventSessionService::Unsubscribe(int64_t eventId)
{
    SGLOGI("eventId=%{public}" PRId64, eventId);
    int32_t code = AuthEventSubscribeManager::GetInstance().IsCallerAllowed();
    if (code != SUCCESS) {
        return code;
    }
    if (!IsValid()) {
        SGLOGE("session is invalid");
        return BAD_PARAM;
    }
    if (IPCSkeleton::GetCallingPid() != pid_) {
        SGLOGE("session not belong to caller");
        return BAD_PARAM;
    }
    XCollie_Utils xcollie("SGIPC_AuthSessionUnsubscribe", XCOLLIE_FLAG);
    return AuthEventSubscribeManager::GetInstance().UnsubscribeAuthEvent(this, eventId);
}

// Client 回填阻断/放行结果
// seqnum 从 event.GetSeqnum() 获取（已填充在 AuthEvent 中）
ErrCode AuthEventSessionService::SetAuthResult(const AuthEvent &event, int32_t authStrategy)
{
    SGLOGI("eventId=%{public}" PRId64 ", authStrategy=%{public}d, seqnum=%{public}" PRId64, event.GetEventId(),
        authStrategy, event.GetSeqnum());
    int32_t code = AuthEventSubscribeManager::GetInstance().IsCallerAllowed();
    if (code != SUCCESS) {
        return code;
    }
    if (!IsValid()) {
        SGLOGE("session is invalid");
        return BAD_PARAM;
    }
    if (IPCSkeleton::GetCallingPid() != pid_) {
        SGLOGE("session not belong to caller");
        return BAD_PARAM;
    }
    XCollie_Utils xcollie("SGIPC_AuthSessionSetAuthResult", XCOLLIE_FLAG);
    return AuthEventSubscribeManager::GetInstance().SetAuthResult(this, event, authStrategy);
}

ErrCode AuthEventSessionService::Destroy()
{
    SGLOGI("Destroy");
    int32_t code = AuthEventSubscribeManager::GetInstance().IsCallerAllowed();
    if (code != SUCCESS) {
        return code;
    }
    if (IPCSkeleton::GetCallingPid() != pid_) {
        SGLOGE("session not belong to caller");
        return BAD_PARAM;
    }
    XCollie_Utils xcollie("SGIPC_AuthSessionDestroy", XCOLLIE_FLAG);
    return AuthEventSubscribeManager::GetInstance().DestroyAuthEventClient(this);
}

AuthEventSessionDeathRecipient::AuthEventSessionDeathRecipient(sptr<AuthEventSessionService> session)
    : session_(std::move(session))
{
}

void AuthEventSessionDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    SGLOGI("auth event subscriber died, clean session");
    if (session_ == nullptr) {
        return;
    }
    AuthEventSubscribeManager::GetInstance().RemoveSession(session_);
}
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
