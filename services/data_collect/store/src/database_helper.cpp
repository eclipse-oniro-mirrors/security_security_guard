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

#include "database_helper.h"
#include <sstream>
#include <array>
#include <cinttypes>
#include "i_model_info.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
DatabaseHelper::DatabaseHelper(std::string dbTable)
{
    dbTable_ = dbTable;
}

int DatabaseHelper::Init()
{
    return SUCCESS;
}

void DatabaseHelper::Release()
{
}

int DatabaseHelper::InsertEvent(const SecEvent& event)
{
    GenericValues values;
    SetValuesBucket(event, values);
    int64_t rowId;
    int ret = Insert(rowId, dbTable_, values);
    if (ret != SUCCESS) {
        SGLOGI("failed to add event, eventId=%{public}" PRId64 ", ret=%{public}d", event.eventId, ret);
        return FAILED;
    }
    return SUCCESS;
}

int DatabaseHelper::QueryAllEvent(std::vector<SecEvent> &events)
{
    return QueryEventBase({}, events, {});
}

int DatabaseHelper::QueryRecentEventByEventId(int64_t eventId, SecEvent &event)
{
    std::vector<SecEvent> results;
    QueryOptions options;
    options.orderBy = std::string(ID) + " DESC";
    options.limit = 1;
    GenericValues conditions;
    conditions.Put(EVENT_ID, std::to_string(eventId));
    int ret = QueryEventBase(conditions, results, options);
    if (ret == SUCCESS && !results.empty()) {
        event = results[0];
        return SUCCESS;
    }
    return FAILED;
}

int DatabaseHelper::QueryRecentEventByEventId(const std::vector<int64_t> &eventIds, std::vector<SecEvent> &events)
{
    if (eventIds.empty()) {
        return FAILED;
    }

    std::vector<std::string> idStrList;
    for (const auto &id: eventIds) {
        idStrList.push_back(std::to_string(id));
    }

    GenericValues conditions;
    conditions.Put(std::string(EVENT_ID) + "_IN", Join(idStrList, ","));

    QueryOptions options;
    options.orderBy = std::string(DATE) + " DESC";
    options.limit = 1;
    int ret = QueryEventBase(conditions, events, options);
    if (ret != SUCCESS) {
        SGLOGE("query fail");
        events.clear();
    }
    return ret;
}

int DatabaseHelper::QueryEventByEventId(int64_t eventId, std::vector<SecEvent> &events)
{
    GenericValues conditions;
    conditions.Put(EVENT_ID, std::to_string(eventId));
    return QueryEventBase(conditions, events);
}

int DatabaseHelper::QueryEventByEventId(std::vector<int64_t> &eventIds, std::vector<SecEvent> &events)
{
    if (eventIds.empty()) {
        return BAD_PARAM;
    }

    std::ostringstream oss;
    for (size_t i = 0; i < eventIds.size(); ++i) {
        if (i > 0) {
            oss << ",";
        }
        oss << eventIds[i];
    }

    GenericValues conditions;
    conditions.Put(std::string(EVENT_ID) + "_IN", oss.str());
    return QueryEventBase(conditions, events);
}

int DatabaseHelper::QueryEventByEventIdAndDate(std::vector<int64_t> &eventIds, std::vector<SecEvent> &events,
    std::string beginTime, std::string endTime)
{
    if (eventIds.empty()) {
        return BAD_PARAM;
    }

    GenericValues conditions;
    conditions.Put(std::string(EVENT_ID) + "_IN", Join(eventIds, ","));
    if (!beginTime.empty()) {
        conditions.Put(std::string(DATE) + "_GE", beginTime);
    }

    if (!endTime.empty()) {
        conditions.Put(std::string(DATE) + "_LT", endTime);
    }
    return QueryEventBase(conditions, events);
}

int DatabaseHelper::QueryEventByEventType(int32_t eventType, std::vector<SecEvent> &events)
{
    GenericValues conditions;
    conditions.Put(EVENT_TYPE, std::to_string(eventType));
    return QueryEventBase(conditions, events);
}

int DatabaseHelper::QueryEventByLevel(int32_t level, std::vector<SecEvent> &events)
{
    GenericValues conditions;
    conditions.Put(DATA_SENSITIVITY_LEVEL, std::to_string(level));
    return QueryEventBase(conditions, events);
}

int DatabaseHelper::QueryEventByOwner(std::string owner, std::vector<SecEvent> &events)
{
    GenericValues conditions;
    std::string safeOwner = FilterSpecialChars(owner);
    conditions.Put(std::string(OWNER) + "_LIKE", "%" + safeOwner + "%");
    return QueryEventBase(conditions, events);
}

int64_t DatabaseHelper::CountAllEvent()
{
    int64_t count;
    int ret = Count(count, dbTable_, {});
    if (ret != SUCCESS) {
        SGLOGE("failed to count event, ret=%{public}d", ret);
    }
    return count;
}

int64_t DatabaseHelper::CountEventByEventId(int64_t eventId)
{
    int64_t count = 0;
    GenericValues conditions;
    conditions.Put(EVENT_ID, std::to_string(eventId));
    int ret = Count(count, dbTable_, conditions);
    if (ret != SUCCESS) {
        SGLOGE("failed to count event, eventId=%{public}" PRId64 ", ret=%{public}d", eventId, ret);
        count = 0;
    }
    return count;
}

int DatabaseHelper::DeleteOldEventByEventId(int64_t eventId, int64_t count)
{
    if (count <= 0 || eventId < 0) {
        return BAD_PARAM;
    }
    GenericValues conditions;
    conditions.Put(EVENT_ID, std::to_string(eventId));
    QueryOptions options;
    options.orderBy = std::string(DATE) + " ASC";
    options.limit = static_cast<int>(count);
    options.columns = {ID};

    std::vector<GenericValues> idResults;
    int ret = Query(dbTable_, conditions, idResults, options);
    if (ret != SUCCESS || idResults.empty()) {
        return ret;
    }

    std::vector<std::string> primaryKeys;
    for (const auto& row: idResults) {
        primaryKeys.push_back(std::to_string(row.GetInt64(ID)));
    }

    GenericValues deleteConditions;
    deleteConditions.Put(std::string(ID) + "_IN", Join(primaryKeys, ","));
    int deleteRows = 0;
    return Delete(deleteRows, dbTable_, deleteConditions);
}

int DatabaseHelper::DeleteAllEventByEventId(int64_t eventId)
{
    if (eventId < 0) {
        return BAD_PARAM;
    }
    GenericValues conditions;
    conditions.Put(EVENT_ID, std::to_string(eventId));
    int deleteRows = 0;
    return Delete(deleteRows, dbTable_, conditions);
}

int DatabaseHelper::FlushAllEvent()
{
    return SUCCESS;
}

int DatabaseHelper::QueryEventBase(const GenericValues &conditions, std::vector<SecEvent> &events,
    const QueryOptions &options)
{
    std::vector<GenericValues> queryResults;
    QueryOptions baseOptions = options;
    baseOptions.columns = {EVENT_ID, VERSION, DATE, CONTENT, USER_ID, DEVICE_ID};

    int ret = Query(dbTable_, conditions, queryResults, baseOptions);
    if (ret != SUCCESS) {
        return ret;
    }

    for (const auto& row : queryResults) {
        events.emplace_back(
            SecEvent{
                .eventId = row.GetInt64(EVENT_ID),
                .date = row.GetString(DATE),
                .content = row.GetString(CONTENT),
                .userId = static_cast<int32_t>(row.GetInt64(USER_ID)),
                .deviceId = row.GetString(DEVICE_ID)
            }
        );
    }

    return SUCCESS;
}

void DatabaseHelper::SetValuesBucket(const SecEvent &event, GenericValues &values)
{
    values.Put(EVENT_ID, event.eventId);
    values.Put(VERSION, event.version);
    values.Put(DATE, event.date);
    values.Put(CONTENT, event.content);
    values.Put(EVENT_TYPE, event.eventType);
    values.Put(DATA_SENSITIVITY_LEVEL, event.dataSensitivityLevel);
    values.Put(OWNER, event.owner);
    values.Put(USER_ID, event.userId);
    values.Put(DEVICE_ID, event.deviceId);
}

std::string DatabaseHelper::CreateTable()
{
    std::string table;
    table.append("CREATE TABLE IF NOT EXISTS ").append(dbTable_);
    table.append("(").append(ID).append(" INTEGER PRIMARY KEY AUTOINCREMENT, ");
    table.append(EVENT_ID).append(" INTEGER NOT NULL, ");
    table.append(VERSION).append(" TEXT NOT NULL, ");
    table.append(DATE).append(" TEXT NOT NULL, ");
    table.append(CONTENT).append(" TEXT NOT NULL, ");
    table.append(EVENT_TYPE).append(" INTEGER NOT NULL, ");
    table.append(DATA_SENSITIVITY_LEVEL).append(" INTEGER NOT NULL, ");
    table.append(OWNER).append(" TEXT NOT NULL, ");
    table.append(USER_ID).append(" INTEGER NOT NULL, ");
    table.append(DEVICE_ID).append(" TEXT NOT NULL)");
    return table;
}

std::string DatabaseHelper::FilterSpecialChars(const std::string &input)
{
    std::string filtered;
    for (auto c : input) {
        if (isalnum(c) || c == '_' || c == '%') {
            filtered += c;
        }
    }

    return filtered;
}

std::string DatabaseHelper::Join(const std::vector<int64_t> &vec, const std::string delimiter)
{
    if (vec.empty()) {
        return "";
    }

    std::ostringstream oss;
    oss << vec[0];

    for (size_t i = 1; i < vec.size(); ++i) {
        oss << delimiter << vec[i];
    }

    return oss.str();
}

std::string DatabaseHelper::Join(const std::vector<std::string> &vec, const std::string delimiter)
{
    if (vec.empty()) {
        return "";
    }

    std::string result;
    bool isFirst = true;
    for (const auto &str : vec) {
        if (!isFirst) {
            result += delimiter;
        }
        result += str;
        isFirst = false;
    }

    return result;
}

void DatabaseHelper::CommitEvent()
{
    Commit();
}

void DatabaseHelper::BeginTransactionEvent()
{
    BeginTransaction();
}
} // namespace OHOS::Security::SecurityGuard