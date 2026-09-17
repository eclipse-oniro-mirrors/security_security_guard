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

#include "client_auth_result.h"

namespace OHOS::Security::SecurityGuard {
bool ClientAuthResult::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(clientId_)) {
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(authStrategy_))) {
        return false;
    }
    return true;
}

bool ClientAuthResult::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString(clientId_)) {
        return false;
    }
    int32_t strategy = 0;
    if (!parcel.ReadInt32(strategy)) {
        return false;
    }
    authStrategy_ = static_cast<AuthStrategy>(strategy);
    return true;
}

ClientAuthResult *ClientAuthResult::Unmarshalling(Parcel &parcel)
{
    auto *obj = new (std::nothrow) ClientAuthResult();
    if (obj == nullptr) {
        return nullptr;
    }
    if (!obj->ReadFromParcel(parcel)) {
        delete obj;
        return nullptr;
    }
    return obj;
}
} // namespace OHOS::Security::SecurityGuard
