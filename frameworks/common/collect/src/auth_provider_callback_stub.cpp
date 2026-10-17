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

#include "auth_provider_callback_stub.h"

#include <memory>

#include "message_parcel.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
namespace OHOS::Security::SecurityGuard {
int32_t AuthProviderCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    if (AuthProviderCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        SGLOGE("Descriptor error");
        return NO_PERMISSION;
    }
    if (code == AuthProviderCallbackStub::CMD_ON_CLIENT_STATUS_CHANGED) {
        int32_t size = 0;
        if (!data.ReadInt32(size)) {
            SGLOGE("read size fail");
            return BAD_PARAM;
        }
        if (size < 0) {
            SGLOGE("invalid size");
            return BAD_PARAM;
        }
        std::vector<AuthClientInfo> clientsInfo;
        for (int32_t i = 0; i < size; ++i) {
            // RAII: unique_ptr 接管裸指针，emplace_back 抛 bad_alloc 时自动释放，避免内存泄漏
            auto item = std::unique_ptr<AuthClientInfo>(AuthClientInfo::Unmarshalling(data));
            if (item == nullptr) {
                SGLOGE("read auth client info fail");
                return BAD_PARAM;
            }
            clientsInfo.emplace_back(*item);
        }
        return OnClientStatusChanged(clientsInfo);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
