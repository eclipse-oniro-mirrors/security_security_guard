/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "sg_sqlite_helper.h"
#include "security_guard_log.h"
#include "security_guard_define.h"
#include <sstream>
#include <string>

namespace OHOS::Security::SecurityGuard {
SgSqliteHelper::SgSqliteHelper(const std::string &dbName, const std::string &dbPath, int version,
    const std::vector<std::string> &createSqls) : SqliteHelper(dbName, dbPath, version), createSqls_(createSqls)
{
    Open();
}

SgSqliteHelper::~SgSqliteHelper()
{
    Close();
}
void SgSqliteHelper::OnCreate()
{
    SGLOGI("db create");
    int32_t ret = FAILED;
    size_t size = createSqls_.size();
    if (size == 0) {
        return;
    }
    for (size_t i = 0; i < size; i++) {
        ret = ExecuteSql(createSqls_[i]);
        if (ret != 0) {
            SGLOGE("execute create sql failed, ret=%{public}d, sql=%{private}s", ret, createSqls_[i].c_str());
        }
    }
    return;
}

void SgSqliteHelper::OnUpdate()
{
    return;
}

int SgSqliteHelper::Insert(int64_t &outRowId, const std::string &table, const GenericValues &values)
{
    if (table.empty() || values.GetAllKeys().empty()) {
        SGLOGE("invalid param");
        return FAILED;
    }

    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(rwLock_);
    std::string sql = BuildInsertSql(table, values);
    if (sql.empty()) {
        return FAILED;
    }

    Statement stmt = Prepare(sql);
    std::vector<std::string> keys = values.GetAllKeys();
    for (const auto &key : keys) {
        VariantValue val = values.Get(key);
        if (val.GetType() == ValueType::TYPE_NULL) {
            continue;
        }
        stmt.Bind(key, val);
    }

    Statement::State execRet = stmt.Step();
    if (execRet != Statement::DONE) {
        SGLOGE("insert value fail err %{public}d", execRet);
        return FAILED;
    }

    outRowId = sqlite3_last_insert_rowid(GetDb());
    return SUCCESS;
}

int SgSqliteHelper::BatchInsert(int64_t &outInsertNum, const std::string &table,
    const std::vector<GenericValues> &initialBatchValues)
{
    (void)outInsertNum;
    (void)table;
    (void)initialBatchValues;
    return SUCCESS;
}

int SgSqliteHelper::Update(int &changedRows, const std::string &table, const GenericValues &value)
{
    (void)changedRows;
    (void)table;
    (void)value;
    return SUCCESS;
}

int SgSqliteHelper::Delete(int &deletedRows, const std::string &table, const GenericValues &conditions)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(rwLock_);
    Statement stmt = PrepareDeleteStmt(table, conditions);
    if (stmt.Step() == Statement::DONE) {
        deletedRows = sqlite3_changes(GetDb());
        return SUCCESS;
    }
    return FAILED;
}

int SgSqliteHelper::Attach(const std::string &alias, const std::string &pathName,
    const std::vector<uint8_t> destEncryptKey)
{
    (void)alias;
    (void)pathName;
    (void)destEncryptKey;
    return SUCCESS;
}

int SgSqliteHelper::ExecuteSql(const std::string &sql)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(rwLock_);
    return SqliteHelper::ExecuteSql(sql);
}

int SgSqliteHelper::ExecuteAndGetLong(int64_t &outValue, const std::string &sql,
    const std::vector<std::string> &bindArgs)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(rwLock_);
    Statement stmt = Prepare(sql);
    for (size_t i = 0; (i < bindArgs.size()) && (i < INT32_MAX); ++i) {
        stmt.Bind(static_cast<int32_t>(i + 1), bindArgs[i]);
    }

    if (stmt.Step() == Statement::ROW) {
        outValue = stmt.GetColumnInt64(0);
        return SUCCESS;
    }
    return FAILED;
}

int SgSqliteHelper::Count(int64_t &outValue, const std::string &table, const GenericValues &conditions,
                          const QueryOptions &options)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(rwLock_);
    Statement stmt = PrepareCountStmt(table, conditions, options);
    Statement::State execRet = stmt.Step();
    if (execRet == Statement::ROW) {
        outValue = stmt.GetColumnInt64(0);
        return SUCCESS;
    }
    SGLOGE("Count value fail err %{public}d", execRet);
    return FAILED;
}

GenericValues SgSqliteHelper::ExecuteRowData(Statement &stmt)
{
    GenericValues row;
    const int columnCount = stmt.GetColumnCount();
    for (int i = 0; i < columnCount; ++i) {
        VariantValue value = stmt.GetValue(i, true);
        const std::string columnName = stmt.GetColumnName(i);
        switch (value.GetType()) {
            case ValueType::TYPE_INT:
                row.Put(columnName, value.GetInt());
                break;
            case ValueType::TYPE_INT64:
                row.Put(columnName, value.GetInt64());
                break;
            case ValueType::TYPE_STRING:
                row.Put(columnName, value.GetString());
                break;
            default:
                row.Put(columnName, "");
                break;
        }
    }

    return row;
}

int SgSqliteHelper::Query(const std::string &table, const GenericValues &conditions,
    std::vector<GenericValues> &results, const QueryOptions &options)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(rwLock_);
    std::string sql = BuildSelectSql(table, conditions, options);
    if (sql.empty()) {
        SGLOGE("BuildSelectSql fail");
        return FAILED;
    }

    Statement stmt = PrepareBoundStateStmt(sql, conditions);
    while (stmt.Step() == Statement::ROW) {
        results.emplace_back(ExecuteRowData(stmt));
    }
    return SUCCESS;
}

std::string SgSqliteHelper::BuildInsertSql(const std::string &table, const GenericValues &values)
{
    std::vector<std::string> keys = values.GetAllKeys();
    if (keys.empty()) {
        SGLOGE("invalid param");
        return "";
    }

    std::ostringstream oss;
    oss << " INSERT INTO " << table << " (";
    for (size_t i = 0; i < keys.size(); ++i) {
        oss << keys[i];
        if (i != keys.size() - 1) {
            oss << ",";
        }
    }

    oss << ") VALUES (";
    for (size_t i = 0; i < keys.size(); ++i) {
        oss << ":" << keys[i];
        if (i != keys.size() - 1) {
            oss << ",";
        }
    }
    oss << ")";

    return oss.str();
}

std::string SgSqliteHelper::BuildUpdateSql(const std::string &table, const GenericValues &values,
    const std::string &where)
{
    auto keys = values.GetAllKeys();
    if (keys.empty()) {
        SGLOGE("update values is empty");
        return "";
    }

    std::string setClause;
    for (size_t i = 0; i < keys.size(); ++i) {
        setClause += keys[i] + "=?";
        if (i != keys.size() - 1) {
            setClause += ",";
        }
    }
    std::string sql = "UPDATE " + table + " SET " + setClause;
    if (!where.empty()) {
        sql += " WHERE " + where;
    }
    return sql;
}

std::string SgSqliteHelper::BuildSelectSql(const std::string &table, const GenericValues &conditions,
    const QueryOptions &options)
{
    std::string columns = options.columns.empty() ? "*" : Join(options.columns, ", ");
    std::string sql = "SELECT " + columns + " FROM " + table;
    std::string whereClause = BuildWhereClause(conditions);
    if (!whereClause.empty()) {
        sql += " WHERE " + whereClause;
    }
    if (!options.orderBy.empty()) {
        sql += " ORDER BY " + options.orderBy;
    }
    if (options.limit > 0) {
        sql += " LIMIT " + std::to_string(options.limit);
    }

    return sql;
}

std::string SgSqliteHelper::BuildInPlaceholders(const std::string &key, const std::string &values)
{
    auto items = Split(values, ',');
    std::vector<std::string> placeholders;
    for (size_t i = 0; i < items.size(); ++i) {
        placeholders.push_back(":" + key + "_" + std::to_string(i));
    }

    return Join(placeholders, ",");
}

std::vector<std::string> SgSqliteHelper::Split(const std::string &s, char delimiter)
{
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenSteam(s);
    while (std::getline(tokenSteam, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

Statement SgSqliteHelper::PrepareBoundStateStmt(const std::string &sql, const GenericValues &conditions)
{
    Statement stmt = Prepare(sql);
    auto keys = conditions.GetAllKeys();
    for (const auto& key: keys) {
        VariantValue value = conditions.Get(key);
        if (key.find("_IN") != std::string::npos) {
            auto items = Split(value.GetString(), ',');
            for (size_t i = 0; i < items.size(); ++i) {
                const std::string paramName = key + "_" + std::to_string(i);
                stmt.Bind(paramName, VariantValue(items[i]));
            }
            continue;
        }

        if (value.GetType() == ValueType::TYPE_INT) {
            stmt.Bind(key, VariantValue(value.GetInt()));
        } else if (value.GetType() == ValueType::TYPE_INT64) {
            stmt.Bind(key, VariantValue(value.GetInt64()));
        } else if (value.GetType() == ValueType::TYPE_STRING) {
            stmt.Bind(key, VariantValue(value.GetString()));
        }
    }
    return stmt;
}

bool SgSqliteHelper::EndWith(const std::string &str, const std::string &suffix) const
{
    if (str.length() < suffix.length()) {
        return false;
    }

    return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
}

std::string SgSqliteHelper::BuildWhereClause(const GenericValues &conditions)
{
    std::vector<std::string> clauses;
    std::vector<std::string> ops = {"_IN", "_GE", "_LT", "_LIKE"};

    auto keys = conditions.GetAllKeys();
    for (const auto& key : keys) {
        std::string opFound;
        std::string field = key;

        for (const auto& op: ops) {
            if (EndWith(key, op)) {
                opFound = op.substr(1);
                field = key.substr(0, key.size() - op.size());
                break;
            }
        }

        if (opFound.empty()) {
            clauses.push_back(key + " = :" + key);
            continue;
        }

        if (opFound == "IN") {
            std::string placeholders = BuildInPlaceholders(key, conditions.Get(key).GetString());
            clauses.push_back(field + " IN (" + placeholders + ")");
        } else if (opFound == "GE") {
            clauses.push_back(field + " >= :" + key);
        } else if (opFound == "LT") {
            clauses.push_back(field + " < :" + key);
        } else if (opFound == "LIKE") {
            clauses.push_back(field + " LIKE :" + key);
        }
    }

    return clauses.empty() ? "" : Join(clauses, " AND ");
}

Statement SgSqliteHelper::PrepareCountStmt(const std::string &table, const GenericValues &conditions,
    const QueryOptions &options)
{
    std::string sql = "SELECT COUNT(*) FROM " + table;
    std::string where = BuildWhereClause(conditions);
    if (!where.empty()) {
        sql += " WHERE " + where;
    }

    return PrepareBoundStateStmt(sql, conditions);
}

Statement SgSqliteHelper::PrepareDeleteStmt(const std::string &table, const GenericValues &conditions)
{
    std::string sql = "DELETE FROM " + table;
    std::string where = BuildWhereClause(conditions);
    if (!where.empty()) {
        sql += " WHERE " + where;
    }

    return PrepareBoundStateStmt(sql, conditions);
}

std::string SgSqliteHelper::Join(const std::vector<std::string> &items, const std::string &delimiter)
{
    if (items.empty()) {
        return "";
    }

    std::string result;
    bool isFirst = true;
    for (const auto &str : items) {
        if (!isFirst) {
            result += delimiter;
        }

        result += str;
        isFirst = false;
    }

    return result;
}
}
