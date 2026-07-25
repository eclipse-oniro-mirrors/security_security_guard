/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef SECURITY_COLLECTOR_SECURITY_EVENT_RULE_H
#define SECURITY_COLLECTOR_SECURITY_EVENT_RULE_H

#include <string>

#include "parcel.h"

namespace OHOS::Security::SecurityCollector {
class SecurityEventRuler : public Parcelable {
public:
    SecurityEventRuler() = default;
    SecurityEventRuler(int64_t eventId, const std::string &beginTime = "", const std::string &endTime = "",
        const std::string &param = "")
        : eventId_(eventId), beginTime_(beginTime), endTime_(endTime), param_(param) {};
    ~SecurityEventRuler() override = default;

    int64_t GetEventId() const { return eventId_; };
    std::string GetBeginTime() const { return beginTime_; };
    std::string GetEndTime() const { return endTime_; };
    std::string GetParam() const { return param_; };
    bool Marshalling(Parcel& parcel) const override
    {
        if (!parcel.WriteInt64(eventId_)) {
            return false;
        }
        if (!parcel.WriteString(beginTime_)) {
            return false;
        }
        if (!parcel.WriteString(endTime_)) {
            return false;
        }
        if (!parcel.WriteString(param_)) {
            return false;
        }
        return true;
    };

    bool ReadFromParcel(Parcel &parcel)
    {
        if (!parcel.ReadInt64(eventId_)) {
            return false;
        }
        if (!parcel.ReadString(beginTime_)) {
            return false;
        }
        if (!parcel.ReadString(endTime_)) {
            return false;
        }
        if (!parcel.ReadString(param_)) {
            return false;
        }
        return true;
    };

    static SecurityEventRuler* Unmarshalling(Parcel& parcel)
    {
        SecurityEventRuler *ruler = new (std::nothrow) SecurityEventRuler();
        if (ruler != nullptr && !ruler->ReadFromParcel(parcel)) {
            delete ruler;
            ruler = nullptr;
        }
        return ruler;
    };

private:
    int64_t eventId_;
    std::string beginTime_;
    std::string endTime_;
    std::string param_;
};
} // namespace OHOS::Security::SecurityCollector

#endif // SECURITY_COLLECTOR_SECURITY_EVENT_RULE_H
