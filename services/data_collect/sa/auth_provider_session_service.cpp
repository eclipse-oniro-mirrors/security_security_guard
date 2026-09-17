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

#include "auth_provider_session_service.h"

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE

#include "ipc_skeleton.h"
#ifdef HICOLLIE_ENABLE
#include "xcollie/xcollie_define.h"
#endif
#include "xcollie_utils.h"

#include "auth_coordinator.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
namespace {
#ifdef HICOLLIE_ENABLE
constexpr uint32_t XCOLLIE_FLAG = OHOS::HiviewDFX::XCOLLIE_FLAG_LOG | OHOS::HiviewDFX::XCOLLIE_FLAG_RECOVERY;
#else
constexpr uint32_t XCOLLIE_FLAG = 0;
#endif
}

AuthProviderSessionService::AuthProviderSessionService(pid_t callerPid, int32_t callerUid,
    const std::string &serviceId, const sptr<IRemoteObject> &callback)
    : pid_(callerPid), uid_(callerUid), serviceId_(serviceId), callback_(callback)
{
}

// 验收: Provider 请求鉴权结果
// 流程: 权限校验 → 会话有效性校验 → pid 归属校验 → 转调 AuthCoordinator::RequestAuthResult
// 异步返回: IPC 异步返回结果给 sg kit，sg kit 异步返回调用结果给事件提供者
ErrCode AuthProviderSessionService::RequestAuthResult(const AuthEventInfo &event,
    const sptr<IRemoteObject> &resultCallback, AuthResult &result)
{
    SGLOGI("eventId=%{public}" PRId64 ", serviceId=%{public}s", event.GetEventId(), serviceId_.c_str());
    int32_t code = AuthCoordinator::GetInstance().IsProviderAllowed();
    if (code != SUCCESS) {
        SGLOGE("permission denied");
        return code;
    }
    if (!IsValid()) {
        SGLOGE("provider is invalid");
        return BAD_PARAM;
    }
    if (IPCSkeleton::GetCallingPid() != pid_) {
        SGLOGE("provider not belong to caller, callerPid=%{private}d, sessionPid=%{private}d",
            IPCSkeleton::GetCallingPid(), static_cast<int32_t>(pid_));
        return BAD_PARAM;
    }
    XCollie_Utils xcollie("SGIPC_RequestAuthResult", XCOLLIE_FLAG);
    return AuthCoordinator::GetInstance().RequestAuthResult(this, event, resultCallback, result);
}

// 验收: Provider 销毁（幂等，返回 void；销毁后再调 RequestAuthResult → BAD_PARAM）
void AuthProviderSessionService::Destroy()
{
    SGLOGI("enter, serviceId=%{public}s", serviceId_.c_str());
    int32_t code = AuthCoordinator::GetInstance().IsProviderAllowed();
    if (code != SUCCESS) {
        SGLOGE("permission denied");
        return;
    }
    if (IPCSkeleton::GetCallingPid() != pid_) {
        SGLOGE("provider not belong to caller, callerPid=%{private}d, sessionPid=%{private}d",
            IPCSkeleton::GetCallingPid(), static_cast<int32_t>(pid_));
        return;
    }
    XCollie_Utils xcollie("SGIPC_DestroyAuthProvider", XCOLLIE_FLAG);
    AuthCoordinator::GetInstance().DestroyAuthProvider(this);
}
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
