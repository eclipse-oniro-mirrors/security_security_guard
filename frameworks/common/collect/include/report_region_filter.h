/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef SECURITY_GUARD_REPORT_REGION_FILTER_H
#define SECURITY_GUARD_REPORT_REGION_FILTER_H

#include <chrono>
#include <cstdint>
#include <ctime>
#include <mutex>
#include <string>
#include <unordered_set>

#include "report_region_policy.h"

namespace OHOS::Security::SecurityGuard {
class ReportRegionFilter {
public:
    static ReportRegionFilter &GetInstance();
    void Init();
    std::string FilterContent(int64_t eventId, const std::string &content);

private:
    ReportRegionFilter() = default;
    ~ReportRegionFilter() = default;
    ReportRegionFilter(const ReportRegionFilter &) = delete;
    ReportRegionFilter &operator = (const ReportRegionFilter &) = delete;

    std::string QueryCountryCode();
    time_t GetConfigMtime() const;
    bool IsCountryCodeExpired() const;
    void ReloadPolicy(time_t currentMtime);
    void TryReloadIfChanged();
    std::string RemoveBlockedFields(int64_t eventId, const std::string &content,
        const std::unordered_set<std::string> &blockedFields);

private:
    static constexpr int64_t COUNTRY_CODE_TTL_MS = 5 * 60 * 1000;
    std::mutex mutex_ {};
    bool loaded_ {false};
    bool countryCodeValid_ {false};
    std::string cachedCountryCode_ {};
    std::chrono::steady_clock::time_point lastCountryCodeTime_ {};
    time_t lastConfigMtime_ {0};
    ReportRegionPolicy policy_ {};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_REPORT_REGION_FILTER_H