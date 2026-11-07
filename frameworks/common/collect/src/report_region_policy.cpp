/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 */
#include "report_region_policy.h"

#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include "cJSON.h"
#include "securec.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    const char *JSON_KEY_VERSION = "version";
    const char *JSON_KEY_POLICIES = "policies";
    const char *JSON_KEY_BLOCKED_FIELDS = "blockedFields";
    const std::string CONFIG_PERSISTENT_PATH = "/data/service/el1/public/security_guard/report_region_policy.json";
    const std::string CONFIG_PRESET_PATH = "/system/etc/report_region_policy.json";
    const size_t CONFIG_MAX_SIZE = 1 * 1024 * 1024;  // 1MB
    const int EVENT_KEY_BUF_SIZE = 32;
}

static bool ReadFileContent(const std::string &path, size_t maxSize, std::string &content)
{
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return false;
    }
    if (st.st_size <= 0 || static_cast<size_t>(st.st_size) > maxSize) {
        SGLOGE("ReadFileContent: file size invalid, path=%{public}s, size=%{public}lld",
            path.c_str(), static_cast<long long>(st.st_size));
        return false;
    }
    std::ifstream ifs(path, std::ios::in);
    if (!ifs.is_open()) {
        return false;
    }
    std::stringstream ss;
    ss << ifs.rdbuf();
    content = ss.str();
    return true;
}

bool ReportRegionPolicy::LoadForCountry(const std::string &countryCode)
{
    SGLOGI("LoadForCountry: countryCode=%{public}s", countryCode.c_str());
    // 国家码为空时，标记无效，所有事件放行
    if (countryCode.empty()) {
        configValid_ = false;
        cachedEventMap_.clear();
        cachedCountryCode_.clear();
        return true;
    }
    return ReadAndParse(countryCode);
}

bool ReportRegionPolicy::ReadAndParse(const std::string &countryCode)
{
    std::string content;
    if (!ReadFileContent(CONFIG_PERSISTENT_PATH, CONFIG_MAX_SIZE, content) &&
        !ReadFileContent(CONFIG_PRESET_PATH, CONFIG_MAX_SIZE, content)) {
        SGLOGW("ReadAndParse: no config file found, all events pass through");
        configValid_ = false;
        cachedEventMap_.clear();
        return true;
    }

    if (content.empty()) {
        SGLOGE("ReadAndParse: content is empty");
        configValid_ = false;
        cachedEventMap_.clear();
        return false;
    }

    cJSON *root = cJSON_Parse(content.c_str());
    if (root == nullptr) {
        SGLOGE("ReadAndParse: cJSON_Parse failed");
        configValid_ = false;
        cachedEventMap_.clear();
        return false;
    }

    std::string version;
    std::unordered_map<std::string, EventFieldRule> newEventMap;
    bool ok = ParseCountryPolicy(root, countryCode, version, newEventMap);
    cJSON_Delete(root);
    if (!ok) {
        configValid_ = false;
        cachedEventMap_.clear();
        return false;
    }
    cachedEventMap_ = std::move(newEventMap);
    cachedCountryCode_ = countryCode;
    version_ = std::move(version);
    configValid_ = true;
    SGLOGI("ReadAndParse: success, countryCode=%{public}s, eventCount=%{public}zu",
        countryCode.c_str(), cachedEventMap_.size());
    return true;
}

bool ReportRegionPolicy::ParseCountryPolicy(cJSON *root, const std::string &countryCode,
    std::string &version, std::unordered_map<std::string, EventFieldRule> &newEventMap)
{
    cJSON *versionItem = cJSON_GetObjectItem(root, JSON_KEY_VERSION);
    if (versionItem != nullptr && cJSON_IsString(versionItem)) {
        version = versionItem->valuestring;
    } else {
        SGLOGW("ParseCountryPolicy: missing version field");
    }
    cJSON *policies = cJSON_GetObjectItem(root, JSON_KEY_POLICIES);
    if (policies == nullptr || !cJSON_IsObject(policies)) {
        SGLOGE("ParseCountryPolicy: missing policies object, config invalid");
        return false;
    }
    cJSON *country = cJSON_GetObjectItem(policies, countryCode.c_str());
    if (country == nullptr || !cJSON_IsObject(country)) {
        // 国家码不在配置中，策略为空但仍标记有效（放行）
        SGLOGI("ParseCountryPolicy: country=%{public}s not found in policies", countryCode.c_str());
        return true;
    }
    cJSON *event = nullptr;
    cJSON_ArrayForEach(event, country) {
        if (event == nullptr || !cJSON_IsObject(event)) {
            continue;
        }
        std::string eventKey = event->string ? event->string : "";
        if (eventKey.empty()) {
            continue;
        }
        EventFieldRule rule;
        ParseEventRule(event, rule);
        newEventMap[eventKey] = std::move(rule);
    }
    return true;
}

void ReportRegionPolicy::ParseEventRule(const cJSON *event, EventFieldRule &rule)
{
    cJSON *blockedFields = cJSON_GetObjectItem(event, JSON_KEY_BLOCKED_FIELDS);
    if (blockedFields == nullptr || !cJSON_IsArray(blockedFields)) {
        return;
    }
    int size = cJSON_GetArraySize(blockedFields);
    for (int i = 0; i < size; i++) {
        cJSON *field = cJSON_GetArrayItem(blockedFields, i);
        if (field != nullptr && cJSON_IsString(field)) {
            rule.blockedFields.emplace(field->valuestring);
        }
    }
}

bool ReportRegionPolicy::IsConfigValid() const
{
    return configValid_;
}

std::string ReportRegionPolicy::GetVersion() const
{
    return version_;
}

bool ReportRegionPolicy::GetBlockedFields(int64_t eventId,
    std::unordered_set<std::string> &blockedFields) const
{
    blockedFields.clear();
    if (!configValid_) {
        return false;
    }
    // eventId 在配置中以十六进制字符串表示，如 "0x01C001101"
    // eventId 为 int64_t，使用 %09llX 格式化以避免高位截断；截断时 snprintf_s 返回负值
    char eventKeyBuf[EVENT_KEY_BUF_SIZE] = {0};
    int ret = snprintf_s(eventKeyBuf, sizeof(eventKeyBuf), sizeof(eventKeyBuf) - 1,
        "0x%09llX", static_cast<long long>(eventId));
    if (ret < 0) {
        SGLOGE("GetBlockedFields: snprintf_s failed, ret=%{public}d", ret);
        return false;
    }
    std::string eventKey(eventKeyBuf);
    auto eventIt = cachedEventMap_.find(eventKey);
    if (eventIt == cachedEventMap_.end()) {
        return false;
    }
    blockedFields = eventIt->second.blockedFields;
    return true;
}

}  // namespace OHOS::Security::SecurityGuard