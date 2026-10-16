/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SECURITY_GUARD_AUTH_EVENT_CALLBACK_PROXY_H
#define SECURITY_GUARD_AUTH_EVENT_CALLBACK_PROXY_H
#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE

#include "iremote_object.h"
#include "iremote_proxy.h"
#include "nocopyable.h"

#include "i_auth_event_callback.h"

namespace OHOS::Security::SecurityGuard {
class AuthEventCallbackProxy : public IRemoteProxy<IAuthEventCallback>, public NoCopyable {
public:
    explicit AuthEventCallbackProxy(const sptr<IRemoteObject> &impl);
    ~AuthEventCallbackProxy() override = default;
    int32_t OnAuthEvent(const AuthEvent &event, int64_t seqnum) override;

private:
    static inline BrokerDelegator<AuthEventCallbackProxy> delegator_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
#endif // SECURITY_GUARD_AUTH_EVENT_CALLBACK_PROXY_H
