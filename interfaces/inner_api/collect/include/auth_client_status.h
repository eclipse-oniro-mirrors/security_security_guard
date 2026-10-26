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

#ifndef SECURITY_GUARD_AUTH_CLIENT_STATUS_H
#define SECURITY_GUARD_AUTH_CLIENT_STATUS_H

#include <string>

#include "parcel.h"

namespace OHOS::Security::SecurityGuard {
class AuthClientStatus : public Parcelable {
public:
    AuthClientStatus() = default;
    AuthClientStatus(const std::string &clientId, bool isDegraded)
        : clientId_(clientId), isDegraded_(isDegraded) {};
    ~AuthClientStatus() override = default;

    std::string GetClientId() const { return clientId_; };
    bool IsDegraded() const { return isDegraded_; };
    void SetClientId(const std::string &clientId) { clientId_ = clientId; };
    void SetDegraded(bool isDegraded) { isDegraded_ = isDegraded; };
    bool Marshalling(Parcel &parcel) const override;
    bool ReadFromParcel(Parcel &parcel);
    static AuthClientStatus *Unmarshalling(Parcel &parcel);

private:
    std::string clientId_ {};
    bool isDegraded_ {false};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_CLIENT_STATUS_H
