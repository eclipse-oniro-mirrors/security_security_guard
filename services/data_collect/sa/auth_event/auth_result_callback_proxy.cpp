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

#include "auth_result_callback_proxy.h"

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE

#include "message_parcel.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
int32_t AuthResultCallbackProxy::OnAuthResult(const AuthResult &result)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return FAILED;
    }
    if (!data.WriteParcelable(&result)) {
        SGLOGE("write auth result fail");
        return FAILED;
    }
    MessageParcel reply;
    MessageOption option = { MessageOption::TF_ASYNC };
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        return NULL_OBJECT;
    }
    return remote->SendRequest(CMD_ON_AUTH_RESULT, data, reply, option);
}
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
