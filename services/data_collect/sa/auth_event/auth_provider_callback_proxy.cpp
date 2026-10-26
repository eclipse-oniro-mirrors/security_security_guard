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

#include "auth_provider_callback_proxy.h"

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE

#include "message_parcel.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
int32_t AuthProviderCallbackProxy::OnClientStatusChanged(const std::vector<AuthClientInfo> &clientsInfo)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        SGLOGE("write interface token fail");
        return FAILED;
    }
    if (!data.WriteInt32(static_cast<int32_t>(clientsInfo.size()))) {
        SGLOGE("write size fail");
        return FAILED;
    }
    for (const auto &item : clientsInfo) {
        if (!item.Marshalling(data)) {
            SGLOGE("write auth client info fail");
            return FAILED;
        }
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    return Remote()->SendRequest(CMD_ON_CLIENT_STATUS_CHANGED, data, reply, option);
}
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
