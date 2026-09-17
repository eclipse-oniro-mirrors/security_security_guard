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

#include "auth_client_info.h"

namespace OHOS::Security::SecurityGuard {
bool AuthClientInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(clientId_)) {
        return false;
    }
    if (!parcel.WriteString(bundleName_)) {
        return false;
    }
    if (!parcel.WriteInt64Vector(subscribedEvents_)) {
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(defaultTimeoutStrategy_))) {
        return false;
    }
    if (!parcel.WriteInt32(defaultTimeouts_)) {
        return false;
    }
    return true;
}

bool AuthClientInfo::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString(clientId_)) {
        return false;
    }
    if (!parcel.ReadString(bundleName_)) {
        return false;
    }
    if (!parcel.ReadInt64Vector(&subscribedEvents_)) {
        return false;
    }
    int32_t strategy = 0;
    if (!parcel.ReadInt32(strategy)) {
        return false;
    }
    defaultTimeoutStrategy_ = static_cast<AuthStrategy>(strategy);
    if (!parcel.ReadInt32(defaultTimeouts_)) {
        return false;
    }
    return true;
}

AuthClientInfo *AuthClientInfo::Unmarshalling(Parcel &parcel)
{
    auto *obj = new (std::nothrow) AuthClientInfo();
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
