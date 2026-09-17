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

#ifndef SECURITY_GUARD_CLIENT_AUTH_RESULT_H
#define SECURITY_GUARD_CLIENT_AUTH_RESULT_H

#include <string>

#include "auth_strategy.h"
#include "parcel.h"

namespace OHOS::Security::SecurityGuard {
class ClientAuthResult : public Parcelable {
public:
    ClientAuthResult() = default;
    ClientAuthResult(const std::string &clientId, AuthStrategy authStrategy)
        : clientId_(clientId), authStrategy_(authStrategy) {};
    ~ClientAuthResult() override = default;

    std::string GetClientId() const { return clientId_; };
    AuthStrategy GetAuthStrategy() const { return authStrategy_; };
    void SetClientId(const std::string &clientId) { clientId_ = clientId; };
    void SetAuthStrategy(AuthStrategy authStrategy) { authStrategy_ = authStrategy; };
    bool Marshalling(Parcel &parcel) const override;
    bool ReadFromParcel(Parcel &parcel);
    static ClientAuthResult *Unmarshalling(Parcel &parcel);

private:
    std::string clientId_ {};
    AuthStrategy authStrategy_ {ALLOW};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_CLIENT_AUTH_RESULT_H
