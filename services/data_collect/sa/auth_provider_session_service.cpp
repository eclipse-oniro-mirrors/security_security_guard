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

#include <cinttypes>
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

// IPC 异步应答: 返回码承载校验结果（是否接受请求），最终阻断策略经 resultCallback 回调返回
ErrCode AuthProviderSessionService::RequestAuthResult(const AuthEventInfo &event,
    const sptr<IRemoteObject> &resultCallback)
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
    return AuthCoordinator::GetInstance().RequestAuthResult(this, event, resultCallback);
}

// Provider 销毁（IDL 生成返回 ErrCode，实际不消费返回值）
ErrCode AuthProviderSessionService::Destroy()
{
    SGLOGI("enter, serviceId=%{public}s", serviceId_.c_str());
    int32_t code = AuthCoordinator::GetInstance().IsProviderAllowed();
    if (code != SUCCESS) {
        SGLOGE("permission denied");
        return code;
    }
    if (IPCSkeleton::GetCallingPid() != pid_) {
        SGLOGE("provider not belong to caller, callerPid=%{private}d, sessionPid=%{private}d",
            IPCSkeleton::GetCallingPid(), static_cast<int32_t>(pid_));
        return BAD_PARAM;
    }
    XCollie_Utils xcollie("SGIPC_DestroyAuthProvider", XCOLLIE_FLAG);
    AuthCoordinator::GetInstance().DestroyAuthProvider(this);
    return SUCCESS;
}
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
