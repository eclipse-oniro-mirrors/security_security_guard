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
#include "risk_event_rdb_helper.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
DatabaseHelper &RiskEventRdbHelper::GetInstance()
{
    static RiskEventRdbHelper riskInstance;
    static DatabaseHelper &instance = riskInstance;
    return instance;
}

RiskEventRdbHelper::RiskEventRdbHelper() : DatabaseHelper(RISK_TABLE)
{
    dbPath_ = FOLDER_PATH + "risk_event.db";
}

int RiskEventRdbHelper::Init()
{
    int errCode = -1;
    std::string table = CreateTable();
    std::string index = CreateEventIdIndex();
    std::vector<std::string> createTableVec;
    createTableVec.push_back(table);
    createTableVec.push_back(index);
    CreateRdbStore("risk_event.db", FOLDER_PATH, DB_VERSION, createTableVec, errCode);
    // 库文件 user_version 由其他模块管理（当前已到 3），本组件不做版本迁移、不覆写版本；
    // 每次启动幂等补建表与 event_id 索引，覆盖全新库（OnCreate 已建，此处 no-op）与任意版本存量库。
    // 索引收益：CountEventByEventId（写入路径配额检查）/QueryEventByEventId/Delete 系列免全表扫描
    int ret = ExecuteSql(table);
    if (ret != 0) {
        SGLOGE("execute create table sql failed, ret=%{public}d", ret);
        return ret;
    }
    ret = ExecuteSql(index);
    if (ret != 0) {
        SGLOGE("execute create index sql failed, ret=%{public}d", ret);
        return ret;
    }
    return errCode;
}
} // namespace OHOS::Security::SecurityGuard