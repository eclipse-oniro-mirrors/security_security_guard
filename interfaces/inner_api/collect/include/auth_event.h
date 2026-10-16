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

#ifndef SECURITY_GUARD_AUTH_EVENT_H
#define SECURITY_GUARD_AUTH_EVENT_H

#include <cstdint>
#include <string>

#include "parcel.h"

namespace OHOS::Security::SecurityGuard {
class AuthEvent : public Parcelable {
public:
    AuthEvent() = default;
    AuthEvent(int64_t eventId, const std::string &content = "",
        const std::string &metadata = "") : eventId_(eventId), content_(content), metadata_(metadata) {};
    ~AuthEvent() override = default;

    int64_t GetEventId() const { return eventId_; };
    int64_t GetSeqnum() const { return seqnum_; };
    std::string GetContent() const { return content_; };
    std::string GetMetadata() const { return metadata_; };
    void SetSeqnum(int64_t seqnum) { seqnum_ = seqnum; };
    void SetContent(const std::string &content) { content_ = content; };
    void SetMetadata(const std::string &metadata) { metadata_ = metadata; };
    bool Marshalling(Parcel& parcel) const override;
    bool ReadFromParcel(Parcel &parcel);
    static AuthEvent* Unmarshalling(Parcel& parcel);

private:
    int64_t eventId_ = 0;
    int64_t seqnum_ = 0;
    std::string content_ {};
    std::string metadata_ {};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_H
