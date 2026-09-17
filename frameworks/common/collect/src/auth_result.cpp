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

#include "auth_result.h"

namespace OHOS::Security::SecurityGuard {
bool AuthResult::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(mergedAuthStrategy_))) {
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(clientAuthResults_.size()))) {
        return false;
    }
    for (const auto &item : clientAuthResults_) {
        if (!item.Marshalling(parcel)) {
            return false;
        }
    }
    return true;
}

bool AuthResult::ReadFromParcel(Parcel &parcel)
{
    int32_t strategy = 0;
    if (!parcel.ReadInt32(strategy)) {
        return false;
    }
    mergedAuthStrategy_ = static_cast<AuthStrategy>(strategy);
    int32_t size = 0;
    if (!parcel.ReadInt32(size)) {
        return false;
    }
    if (size < 0) {
        return false;
    }
    clientAuthResults_.clear();
    for (int32_t i = 0; i < size; ++i) {
        auto *item = ClientAuthResult::Unmarshalling(parcel);
        if (item == nullptr) {
            return false;
        }
        clientAuthResults_.emplace_back(*item);
        delete item;
    }
    return true;
}

AuthResult *AuthResult::Unmarshalling(Parcel &parcel)
{
    auto *obj = new (std::nothrow) AuthResult();
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
