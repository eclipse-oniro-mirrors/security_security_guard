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

#include "auth_client_status.h"

namespace OHOS::Security::SecurityGuard {
bool AuthClientStatus::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(clientId_)) {
        return false;
    }
    if (!parcel.WriteBool(isDegrader_)) {
        return false;
    }
    return true;
}

bool AuthClientStatus::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString(clientId_)) {
        return false;
    }
    if (!parcel.ReadBool(isDegrader_)) {
        return false;
    }
    return true;
}

AuthClientStatus *AuthClientStatus::Unmarshalling(Parcel &parcel)
{
    auto *obj = new (std::nothrow) AuthClientStatus();
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
