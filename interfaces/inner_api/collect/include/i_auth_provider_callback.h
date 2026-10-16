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

#ifndef SECURITY_GUARD_I_AUTH_PROVIDER_CALLBACK_H
#define SECURITY_GUARD_I_AUTH_PROVIDER_CALLBACK_H

#include <vector>

#include "auth_client_info.h"
#include "data_collect_manager_service_ipc_interface_code.h"
#include "iremote_broker.h"

namespace OHOS::Security::SecurityGuard {
class IAuthProviderCallback : public IRemoteBroker {
public:
    using InterfaceCode = AuthProviderCallbackInterfaceCode;
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Security.DataCollectManager.AuthProviderCallback");
    enum {
        CMD_ON_CLIENT_STATUS_CHANGED = static_cast<uint32_t>(InterfaceCode::CMD_ON_CLIENT_STATUS_CHANGED),
    };

    virtual int32_t OnClientStatusChanged(const std::vector<AuthClientInfo> &clientsInfo) = 0;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_I_AUTH_PROVIDER_CALLBACK_H
