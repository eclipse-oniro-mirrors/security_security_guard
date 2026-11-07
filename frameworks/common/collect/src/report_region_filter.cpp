/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 */
#include "report_region_filter.h"

#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <cctype>
#include <sys/stat.h>
#include "cJSON.h"
#include "parameter.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    const size_t COUNTRY_CODE_LENGTH = 2;
    const size_t SYSTEM_PARAM_VALUE_MAX_LEN = 128;
    const char *REGION_PARAM_KEY = "const.cust.region";
    const char *SIM_COUNTRY_CODE0_KEY = "telephony.sim.countryCode0";
    const char *SIM_COUNTRY_CODE1_KEY = "telephony.sim.countryCode1";
    const char *LOCALE_PARAM_KEY = "persist.global.locale";
    const std::string CONFIG_PERSISTENT_PATH = "/data/service/el1/public/security_guard/report_region_policy.json";
    const std::string CONFIG_PRESET_PATH = "/system/etc/report_region_policy.json";

    std::string GetParameterValue(const char *paramKey)
    {
        char paramValue[SYSTEM_PARAM_VALUE_MAX_LEN] = {0};
        auto ret = GetParameter(paramKey, "unknown", paramValue, SYSTEM_PARAM_VALUE_MAX_LEN);
        if (ret != static_cast<int32_t>(COUNTRY_CODE_LENGTH)) {
            return "";
        }
        return std::string(paramValue);
    }

    std::string ParseLocaleCountryCode(const std::string &localeStr)
    {
        // 兼容 '-' 和 '_' 分隔符
        size_t posDash = localeStr.rfind('-');
        size_t posUnderscore = localeStr.rfind('_');
        size_t position = std::string::npos;
        if (posDash != std::string::npos && posUnderscore != std::string::npos) {
            position = std::max(posDash, posUnderscore);
        } else if (posDash != std::string::npos) {
            position = posDash;
        } else if (posUnderscore != std::string::npos) {
            position = posUnderscore;
        }
        if (position != std::string::npos && position < localeStr.length() - 1) {
            std::string subString = localeStr.substr(position + 1);
            if (subString.length() != COUNTRY_CODE_LENGTH) {
                return "";
            }
            return subString;
        }
        return "";
    }

    std::string QueryCountryCodeFromProviders()
    {
        // priority: const.cust.region -> SIM0 -> SIM1 -> locale
        std::string code = GetParameterValue(REGION_PARAM_KEY);
        if (!code.empty()) {
            return code;
        }
        code = GetParameterValue(SIM_COUNTRY_CODE0_KEY);
        if (!code.empty()) {
            return code;
        }
        code = GetParameterValue(SIM_COUNTRY_CODE1_KEY);
        if (!code.empty()) {
            return code;
        }
        // locale: parse last segment after '-' or '_'
        char paramValue[SYSTEM_PARAM_VALUE_MAX_LEN] = {0};
        auto ret = GetParameter(LOCALE_PARAM_KEY, "unknown", paramValue, SYSTEM_PARAM_VALUE_MAX_LEN);
        if (ret <= 0) {
            return "";
        }
        return ParseLocaleCountryCode(std::string(paramValue));
    }
}

ReportRegionFilter &ReportRegionFilter::GetInstance()
{
    static ReportRegionFilter instance;
    return instance;
}

void ReportRegionFilter::Init()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (loaded_) {
        return;
    }
    // 先获取国家码（锁内调用 GetParameter，仅在初始化时执行一次）
    cachedCountryCode_ = QueryCountryCode();
    countryCodeValid_ = !cachedCountryCode_.empty();
    lastCountryCodeTime_ = std::chrono::steady_clock::now();

    loaded_ = policy_.LoadForCountry(cachedCountryCode_);

    struct stat st;
    if (stat(CONFIG_PERSISTENT_PATH.c_str(), &st) == 0) {
        lastConfigMtime_ = st.st_mtime;
    } else if (stat(CONFIG_PRESET_PATH.c_str(), &st) == 0) {
        lastConfigMtime_ = st.st_mtime;
    }
    SGLOGI("ReportRegionFilter init: countryCode=%{private}s, valid=%{public}d, loaded=%{public}d",
        cachedCountryCode_.c_str(), countryCodeValid_, loaded_);
}

std::string ReportRegionFilter::QueryCountryCode()
{
    return QueryCountryCodeFromProviders();
}

time_t ReportRegionFilter::GetConfigMtime() const
{
    struct stat st;
    if (stat(CONFIG_PERSISTENT_PATH.c_str(), &st) == 0) {
        return st.st_mtime;
    }
    if (stat(CONFIG_PRESET_PATH.c_str(), &st) == 0) {
        return st.st_mtime;
    }
    return 0;
}

bool ReportRegionFilter::IsCountryCodeExpired() const
{
    if (!countryCodeValid_) {
        return false;
    }
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - lastCountryCodeTime_).count();
    return elapsed >= COUNTRY_CODE_TTL_MS;
}

void ReportRegionFilter::ReloadPolicy(time_t currentMtime)
{
    loaded_ = policy_.LoadForCountry(cachedCountryCode_);
    lastConfigMtime_ = currentMtime;
}

void ReportRegionFilter::TryReloadIfChanged()
{
    time_t currentMtime = GetConfigMtime();
    bool configChanged = (currentMtime != lastConfigMtime_ || !loaded_);
    bool codeExpired = IsCountryCodeExpired();

    if (!codeExpired && !configChanged) {
        return; // 无变化，直接返回
    }

    if (codeExpired) {
        std::string newCode = QueryCountryCode();
        lastCountryCodeTime_ = std::chrono::steady_clock::now();
        bool codeChanged = (newCode != cachedCountryCode_);
        cachedCountryCode_ = newCode;
        countryCodeValid_ = !newCode.empty();
        if (codeChanged || configChanged) {
            SGLOGI("TryReloadIfChanged: countryCode or config changed, reloading, newCode=%{public}s",
                newCode.c_str());
            ReloadPolicy(currentMtime);
        }
    } else {
        SGLOGI("TryReloadIfChanged: config file changed, reloading for countryCode=%{public}s",
            cachedCountryCode_.c_str());
        ReloadPolicy(currentMtime);
    }
}

std::string ReportRegionFilter::RemoveBlockedFields(int64_t eventId, const std::string &content,
    const std::unordered_set<std::string> &blockedFields)
{
    cJSON *root = cJSON_Parse(content.c_str());
    if (root == nullptr) {
        return content;
    }
    if (!cJSON_IsObject(root)) {
        cJSON_Delete(root);
        return content;
    }

    std::string blockedStr;
    for (const auto &f : blockedFields) {
        blockedStr += f + ",";
    }

    int removedCount = 0;
    for (const auto &field : blockedFields) {
        cJSON *item = cJSON_GetObjectItem(root, field.c_str());
        if (item != nullptr) {
            cJSON_DeleteItemFromObject(root, field.c_str());
            removedCount++;
        }
    }

    char *resultStr = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (resultStr == nullptr) {
        return content;
    }
    std::string result(resultStr);
    free(resultStr);
    return result;
}

std::string ReportRegionFilter::FilterContent(int64_t eventId, const std::string &content)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!loaded_) {
        SGLOGI("FilterContent: not loaded, pass through");
        return content;
    }
    TryReloadIfChanged();
    if (!loaded_ || !countryCodeValid_) {
        return content;
    }

    std::unordered_set<std::string> blockedFields;
    bool found = policy_.GetBlockedFields(eventId, blockedFields);
    if (!found || blockedFields.empty()) {
        return content;
    }

    if (content.empty()) {
        return content;
    }

    return RemoveBlockedFields(eventId, content, blockedFields);
}

}  // namespace OHOS::Security::SecurityGuard