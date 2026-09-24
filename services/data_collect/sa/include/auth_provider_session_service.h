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

#ifndef SECURITY_GUARD_AUTH_PROVIDER_SESSION_SERVICE_H
#define SECURITY_GUARD_AUTH_PROVIDER_SESSION_SERVICE_H
#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE

#include <cstdint>
#include <string>

#include "auth_provider_session_stub.h"
#include "iremote_object.h"
#include "nocopyable.h"

namespace OHOS::Security::SecurityGuard {
class AuthProviderSessionService : public AuthProviderSessionStub, public NoCopyable {
public:
    AuthProviderSessionService(pid_t callerPid, int32_t callerUid,
        const std::string &serviceId, const sptr<IRemoteObject> &callback);
    ~AuthProviderSessionService() override = default;

    // IPC 异步应答: 返回码承载校验结果（是否接受请求），最终阻断策略经 resultCallback 回调返回
    ErrCode RequestAuthResult(const AuthEventInfo &event, const sptr<IRemoteObject> &resultCallback) override;
    ErrCode Destroy() override;

    sptr<IRemoteObject> GetCallback() const { return callback_; }
    pid_t GetPid() const { return pid_; }
    int32_t GetUid() const { return uid_; }
    std::string GetServiceId() const { return serviceId_; }
    bool IsValid() const { return valid_; }
    void MarkInvalid() { valid_ = false; }
    void SetDeathRecipient(const sptr<IRemoteObject::DeathRecipient> &recipient) { deathRecipient_ = recipient; }
    sptr<IRemoteObject::DeathRecipient> GetDeathRecipient() const { return deathRecipient_; }

private:
    pid_t pid_ {};
    int32_t uid_ {};
    std::string serviceId_ {};
    sptr<IRemoteObject> callback_ {};
    bool valid_ {true};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ {};
};

class AuthProviderSessionDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit AuthProviderSessionDeathRecipient(sptr<AuthProviderSessionService> provider);
    ~AuthProviderSessionDeathRecipient() override = default;
    void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
private:
    sptr<AuthProviderSessionService> provider_ {};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
#endif // SECURITY_GUARD_AUTH_PROVIDER_SESSION_SERVICE_H
