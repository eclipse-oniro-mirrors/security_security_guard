/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 */

#ifndef SECURITY_GUARD_REPORT_REGION_POLICY_H
#define SECURITY_GUARD_REPORT_REGION_POLICY_H

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

struct cJSON;

namespace OHOS::Security::SecurityGuard {
struct EventFieldRule {
    std::unordered_set<std::string> blockedFields {};
};

class ReportRegionPolicy {
public:
    ReportRegionPolicy() = default;
    ~ReportRegionPolicy() = default;

    bool LoadForCountry(const std::string &countryCode);
    bool IsConfigValid() const;
    std::string GetVersion() const;
    bool GetBlockedFields(int64_t eventId, std::unordered_set<std::string> &blockedFields) const;

private:
    bool ReadAndParse(const std::string &countryCode);
    bool ParseCountryPolicy(cJSON *root, const std::string &countryCode, std::string &version,
        std::unordered_map<std::string, EventFieldRule> &newEventMap);
    void ParseEventRule(const cJSON *event, EventFieldRule &rule);

private:
    bool configValid_ {false};
    std::string cachedCountryCode_ {};
    std::string version_ {};
    std::unordered_map<std::string, EventFieldRule> cachedEventMap_ {};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_REPORT_REGION_POLICY_H