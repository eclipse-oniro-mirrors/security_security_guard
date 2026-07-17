/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef SECURITY_GUARD_RISK_EVENT_RDB_HELPER_H
#define SECURITY_GUARD_RISK_EVENT_RDB_HELPER_H

#include <vector>

#include "gmock/gmock.h"

#include "i_model_info.h"

namespace OHOS::Security::SecurityGuard {
class BaseRiskEventRdbHelper {
public:
    virtual int Init() = 0;
    virtual void Release() = 0;
    virtual int InsertEvent(const SecEvent& event) = 0;
    virtual int QueryAllEvent(std::vector<SecEvent> &events) = 0;
    virtual int QueryRecentEventByEventId(int64_t eventId, SecEvent &event) = 0;
    virtual int QueryRecentEventByEventId(const std::vector<int64_t> &eventId, std::vector<SecEvent> &event) = 0;
    virtual int QueryEventByEventId(int64_t eventId, std::vector<SecEvent> &events) = 0;
    virtual int QueryEventByEventId(std::vector<int64_t> &eventIds, std::vector<SecEvent> &events) = 0;
    virtual int QueryEventByEventIdAndDate(std::vector<int64_t> &eventIds, std::vector<SecEvent> &events,
        std::string beginTime, std::string endTime) = 0;
    virtual int QueryEventByEventType(int32_t eventType, std::vector<SecEvent> &events) = 0;
    virtual int QueryEventByLevel(int32_t level, std::vector<SecEvent> &events) = 0;
    virtual int QueryEventByOwner(std::string owner, std::vector<SecEvent> &events) = 0;
    virtual int64_t CountAllEvent() = 0;
    virtual int64_t CountEventByEventId(int64_t eventId) = 0;
    virtual int DeleteOldEventByEventId(int64_t eventId, int64_t count) = 0;
    virtual int DeleteAllEventByEventId(int64_t eventId) = 0;
    virtual int FlushAllEvent() = 0;
    virtual void CommitEvent() = 0;
    virtual void BeginTransactionEvent() = 0;
};

class RiskEventRdbHelper : public BaseRiskEventRdbHelper {
public:
    static RiskEventRdbHelper &GetInstance()
    {
        static RiskEventRdbHelper instance;
        return instance;
    }
    MOCK_METHOD0(Init, int());
    MOCK_METHOD0(Release, void());
    MOCK_METHOD1(InsertEvent, int(const SecEvent& event));
    MOCK_METHOD1(QueryAllEvent, int(std::vector<SecEvent> &events));
    MOCK_METHOD2(QueryRecentEventByEventId, int(int64_t eventId, SecEvent &event));
    MOCK_METHOD2(QueryRecentEventByEventId, int(const std::vector<int64_t> &eventId, std::vector<SecEvent> &event));
    MOCK_METHOD2(QueryEventByEventId, int(int64_t eventId, std::vector<SecEvent> &events));
    MOCK_METHOD2(QueryEventByEventId, int(std::vector<int64_t> &eventIds, std::vector<SecEvent> &events));
    MOCK_METHOD4(QueryEventByEventIdAndDate, int(std::vector<int64_t> &eventIds, std::vector<SecEvent> &events,
        std::string beginTime, std::string endTime));
    MOCK_METHOD2(QueryEventByEventType, int(int32_t eventType, std::vector<SecEvent> &events));
    MOCK_METHOD2(QueryEventByLevel, int(int32_t level, std::vector<SecEvent> &events));
    MOCK_METHOD2(QueryEventByOwner, int(std::string owner, std::vector<SecEvent> &events));
    MOCK_METHOD0(CountAllEvent, int64_t());
    MOCK_METHOD1(CountEventByEventId, int64_t(int64_t eventId));
    MOCK_METHOD2(DeleteOldEventByEventId, int(int64_t eventId, int64_t count));
    MOCK_METHOD1(DeleteAllEventByEventId, int(int64_t eventId));
    MOCK_METHOD0(FlushAllEvent, int());
    MOCK_METHOD0(CommitEvent, void());
    MOCK_METHOD0(BeginTransactionEvent, void());
};
} // namespace OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_RISK_EVENT_RDB_HELPER_H