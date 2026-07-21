/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "database.h"
#include <thread>
#include "security_guard_log.h"
#include "security_guard_define.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr int32_t MAX_TIMES = 5;
    constexpr int32_t SLEEP_INTERVAL = 500;
}

void Database::CreateRdbStore(const std::string &dbName, const std::string &dbPath, int version,
    const std::vector<std::string> &createSqls, int &errCode)
{
    SGLOGI("EventStore::CreateRdbStore");
    store_ = std::make_shared<SgSqliteHelper>(dbName, dbPath, version, createSqls);
    errCode = 0;
}

int Database::Insert(int64_t &outRowId, const std::string &table, const GenericValues &value)
{
    int ret = IsExistStore();
    if (ret == SUCCESS) {
        ret = store_->Insert(outRowId, table, value);
    }
    return ret;
}

int Database::BatchInsert(int64_t &outInsertNum, const std::string &table,
    const std::vector<GenericValues> &initialBatchValues)
{
    int ret = IsExistStore();
    if (ret == SUCCESS) {
        ret = store_->BatchInsert(outInsertNum, table, initialBatchValues);
    }
    return ret;
}

int Database::Update(int &changedRows, const std::string &table, const GenericValues &value)
{
    int ret = IsExistStore();
    if (ret == SUCCESS) {
        ret = store_->Update(changedRows, table, value);
    }
    return ret;
}

int Database::Delete(int &deletedRows, const std::string &table, const GenericValues &conditions)
{
    int ret = IsExistStore();
    if (ret == SUCCESS) {
        ret = store_->Delete(deletedRows, table, conditions);
    }
    return ret;
}

int Database::Query(const std::string &table, const GenericValues &conditions,
    std::vector<GenericValues> &results, const QueryOptions &options)
{
    int ret = IsExistStore();
    if (ret == SUCCESS) {
        return store_->Query(table, conditions, results, options);
    }
    return ret;
}

int Database::ExecuteSql(const std::string &sql)
{
    int ret = IsExistStore();
    if (ret == SUCCESS) {
        ret = store_->ExecuteSql(sql);
    }
    return ret;
}

int Database::ExecuteAndGetLong(int64_t &outValue, const std::string &sql, const std::vector<std::string> &bindArgs)
{
    int ret = IsExistStore();
    if (ret == SUCCESS) {
        ret = store_->ExecuteAndGetLong(outValue, sql, bindArgs);
    }
    return ret;
}

int Database::Count(int64_t &outValue, const std::string &table, const GenericValues &conditions,
    const QueryOptions &options)
{
    int ret = IsExistStore();
    if (ret == SUCCESS) {
        ret = store_->Count(outValue, table, conditions, options);
    }
    return ret;
}

int Database::BeginTransaction()
{
    int ret = IsExistStore();
    if (ret == SUCCESS) {
        ret = store_->BeginTransaction();
    }
    return ret;
}

int Database::RollBack()
{
    int ret = IsExistStore();
    if (ret == SUCCESS) {
        ret = store_->RollbackTransaction();
    }
    return ret;
}

int Database::Commit()
{
    int ret = IsExistStore();
    if (ret == SUCCESS) {
        ret = store_->CommitTransaction();
    }
    return ret;
}

int Database::Attach(const std::string &alias, const std::string &pathName,
    const std::vector<uint8_t> destEncryptKey)
{
    int ret = IsExistStore();
    if (ret == SUCCESS) {
        ret = store_->Attach(alias, pathName, destEncryptKey);
    }
    return ret;
}

int Database::IsExistStore()
{
    {
        std::lock_guard<ffrt::mutex> lock(storeMutex_);
        if (store_ != nullptr) {
            return SUCCESS;
        }
    }
    int32_t tryTimes = MAX_TIMES;
    while (tryTimes > 0) {
        {
            std::lock_guard<ffrt::mutex> lock(storeMutex_);
            if (store_ != nullptr) {
                return SUCCESS;
            }
        }
        SGLOGW("tryTimes = %{public}d", tryTimes);
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_INTERVAL));
        tryTimes--;
    }

    std::lock_guard<ffrt::mutex> lock(storeMutex_);
    if (store_ == nullptr) {
        SGLOGE("EventStore::IsExistStore NativeRdb::RdbStore is null!");
        return FAILED;
    }
    return SUCCESS;
}
}