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

#ifndef SECURITY_GUARD_AUTH_CLIENT_INFO_H
#define SECURITY_GUARD_AUTH_CLIENT_INFO_H

#include <cstdint>
#include <string>
#include <vector>

#include "auth_strategy.h"
#include "parcel.h"

namespace OHOS::Security::SecurityGuard {
class AuthClientInfo : public Parcelable {
public:
    AuthClientInfo() = default;
    ~AuthClientInfo() override = default;

    std::string GetClientId() const { return clientId_; };
    std::string GetBundleName() const { return bundleName_; };
    std::vector<int64_t> GetSubscribedEvents() const { return subscribedEvents_; };
    AuthStrategy GetDefaultTimeoutStrategy() const { return defaultTimeoutStrategy_; };
    int32_t GetDefaultTimeoutMs() const { return defaultTimeoutMs_; };
    void SetClientId(const std::string &clientId) { clientId_ = clientId; };
    void SetBundleName(const std::string &bundleName) { bundleName_ = bundleName; };
    void SetSubscribedEvents(const std::vector<int64_t> &events) { subscribedEvents_ = events; };
    void SetDefaultTimeoutStrategy(AuthStrategy strategy) { defaultTimeoutStrategy_ = strategy; };
    void SetDefaultTimeoutMs(int32_t timeouts) { defaultTimeoutMs_ = timeouts; };
    bool Marshalling(Parcel &parcel) const override;
    bool ReadFromParcel(Parcel &parcel);
    static AuthClientInfo *Unmarshalling(Parcel &parcel);

private:
    std::string clientId_ {};
    std::string bundleName_ {};
    std::vector<int64_t> subscribedEvents_ {};
    AuthStrategy defaultTimeoutStrategy_ {ALLOW};
    int32_t defaultTimeoutMs_ {400};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_CLIENT_INFO_H
