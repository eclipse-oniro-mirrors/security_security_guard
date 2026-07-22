/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SECURITY_GUARD_EVENT_STORE_H
#define SECURITY_GUARD_EVENT_STORE_H
#include "ffrt.h"
#include "sg_sqlite_helper.h"
#include "i_model_info.h"
#include "store_define.h"

namespace OHOS::Security::SecurityGuard {
class Database {
public:
    Database() = default;
    virtual ~Database() = default;
    void CreateRdbStore(const std::string &dbName, const std::string &dbPath, int version,
        const std::vector<std::string> &createSqls, int &errCode);
    int Insert(int64_t &outRowId, const std::string &table, const GenericValues &value);
    int BatchInsert(int64_t &outInsertNum, const std::string &table,
        const std::vector<GenericValues> &initialBatchValues);
    int Update(int &changedRows, const std::string &table, const GenericValues &value);
    int Delete(int &deletedRows, const std::string &table, const GenericValues &conditions = {});
    int Query(const std::string &table, const GenericValues &conditions,
        std::vector<GenericValues> &results, const QueryOptions &options = {});
    int ExecuteSql(const std::string &sql);
    int ExecuteAndGetLong(int64_t &outValue, const std::string &sql,
        const std::vector<std::string> &bindArgs);
    int Count(int64_t &outValue, const std::string &table,  const GenericValues &conditions = {},
         const QueryOptions &options = {});
    int BeginTransaction();
    int RollBack();
    int Commit();
    int Attach(const std::string &alias, const std::string &pathName,
        const std::vector<uint8_t> destEncryptKey);

private:
    int IsExistStore();
    ffrt::mutex storeMutex_;
    std::shared_ptr<SgSqliteHelper> store_;
};
}  // OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_EVENT_STORE_H