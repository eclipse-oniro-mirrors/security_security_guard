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

#ifndef SECURITY_GUARD_AUTH_EVENT_INFO_H
#define SECURITY_GUARD_AUTH_EVENT_INFO_H

#include <cstdint>
#include <string>
#include <vector>

#include "auth_client_status.h"
#include "parcel.h"

namespace OHOS::Security::SecurityGuard {
class AuthEventInfo : public Parcelable {
public:
    AuthEventInfo() = default;
    AuthEventInfo(int64_t eventId, const std::string &version = "", const std::string &content = "")
        : eventId_(eventId), version_(version), content_(content) {};
    ~AuthEventInfo() override = default;

    int64_t GetEventId() const { return eventId_; };
    std::string GetVersion() const { return version_; };
    std::string GetContent() const { return content_; };
    std::vector<AuthClientStatus> GetClientStatus() const { return clientStatus_; };
    void SetVersion(const std::string &version) { version_ = version; };
    void SetContent(const std::string &content) { content_ = content; };
    void SetClientStatus(const std::vector<AuthClientStatus> &status) { clientStatus_ = status; };
    bool Marshalling(Parcel &parcel) const override;
    bool ReadFromParcel(Parcel &parcel);
    static AuthEventInfo *Unmarshalling(Parcel &parcel);

private:
    int64_t eventId_ = 0;
    std::string version_ {};
    std::string content_ {};
    std::vector<AuthClientStatus> clientStatus_ {};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_INFO_H
