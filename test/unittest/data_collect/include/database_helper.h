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

#ifndef SECURITY_GUARD_DATABASE_HELPER_H
#define SECURITY_GUARD_DATABASE_HELPER_H

#include "database.h"
#include "i_model_info.h"

namespace OHOS::Security::SecurityGuard {
class DatabaseHelper : public Database {
public:
    explicit DatabaseHelper(std::string dbTable);
    ~DatabaseHelper() override = default;
    virtual int Init();
    virtual void Release();
    virtual int InsertEvent(const SecEvent& event);
    virtual int QueryAllEvent(std::vector<SecEvent> &events);
    virtual int QueryRecentEventByEventId(int64_t eventId, SecEvent &event);
    virtual int QueryRecentEventByEventId(const std::vector<int64_t> &eventId, std::vector<SecEvent> &event);
    virtual int QueryEventByEventId(int64_t eventId, std::vector<SecEvent> &events);
    virtual int QueryEventByEventId(std::vector<int64_t> &eventIds, std::vector<SecEvent> &events);
    virtual int QueryEventByEventIdAndDate(std::vector<int64_t> &eventIds, std::vector<SecEvent> &events,
        std::string beginTime, std::string endTime);
    virtual int QueryEventByEventType(int32_t eventType, std::vector<SecEvent> &events);
    virtual int QueryEventByLevel(int32_t level, std::vector<SecEvent> &events);
    virtual int QueryEventByOwner(std::string owner, std::vector<SecEvent> &events);
    virtual int64_t CountAllEvent();
    virtual int64_t CountEventByEventId(int64_t eventId);
    virtual int DeleteOldEventByEventId(int64_t eventId, int64_t count);
    virtual int DeleteAllEventByEventId(int64_t eventId);
    virtual int FlushAllEvent();
    virtual void CommitEvent();
    virtual void BeginTransactionEvent();
protected:
    int QueryEventBase(const GenericValues &conditions, std::vector<SecEvent> &events,
        const QueryOptions &options = {});
    std::string CreateTable();
    void SetValuesBucket(const SecEvent &event, GenericValues &values);
    std::string Join(const std::vector<int64_t> &vec, const std::string delimiter);
    std::string Join(const std::vector<std::string> &vec, const std::string delimiter);
    std::string FilterSpecialChars(const std::string &input);
    std::string dbPath_{};
    std::string dbTable_{};
};
} // namespace OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_DATABASE_HELPER_H