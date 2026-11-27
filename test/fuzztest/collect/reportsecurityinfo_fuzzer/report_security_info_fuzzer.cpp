/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "report_security_info_fuzzer.h"

#include <string>
#include <set>
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <sys/stat.h>
#include <unistd.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "securec.h"
#include "cJSON.h"

#include "security_guard_define.h"
#include "sg_collect_client.h"
#include "security_event_filter.h"

#define private public
#include "report_region_policy.h"
#include "report_region_filter.h"
#undef private

extern "C" int32_t ReportSecurityInfo(const struct EventInfoSt *info);

namespace OHOS {
namespace {
constexpr int MAX_STRING_SIZE = 1024;
}
bool ReportSecurityInfoFuzzTest(FuzzedDataProvider &fdp)
{
    int64_t eventId = fdp.ConsumeIntegral<int64_t>();
    EventInfoSt info;
    info.eventId = eventId;
    std::string version(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    info.version = version.c_str();
    std::string content(fdp.ConsumeRandomLengthString(CONTENT_MAX_LEN - 1));
    (void)memcpy_s(info.content, CONTENT_MAX_LEN, content.c_str(), content.size());
    info.contentLen = content.size();
    ReportSecurityInfo(&info);
    return true;
}

bool ReportSecurityInfoAsyncFuzzTest(FuzzedDataProvider &fdp)
{
    EventInfoSt info;
    info.eventId = fdp.ConsumeIntegral<int64_t>();
    std::string str = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    info.version = str.c_str();
    std::string content(fdp.ConsumeRandomLengthString(CONTENT_MAX_LEN - 1));
    (void)memcpy_s(info.content, CONTENT_MAX_LEN, content.c_str(), content.size());
    info.contentLen = content.size();
    ReportSecurityInfoAsync(&info);
    return true;
}

bool SecurityGuardConfigUpdateFuzzTest(FuzzedDataProvider &fdp)
{
    int32_t fd = fdp.ConsumeIntegral<int32_t>();
    std::string name = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE).c_str();
    SecurityGuardConfigUpdate(fd, name.c_str());
    return true;
}

void SecurityEventFilterWhiteBoxTest()
{
    using namespace ::OHOS::Security::SecurityGuard;
    EventMuteFilter normal;
    normal.eventId = 0x01C001101;
    normal.type = 1;
    normal.isInclude = true;
    normal.mutes = {"fieldA", "fieldB"};
    SecurityEventFilter normalFilter(normal);
    Parcel normalParcel;
    (void)normalFilter.Marshalling(normalParcel);
    (void)normalFilter.GetMuteFilter();
    SecurityEventFilter *parsed = SecurityEventFilter::Unmarshalling(normalParcel);
    delete parsed;

    EventMuteFilter oversized;
    oversized.eventId = 1;
    oversized.type = 1;
    oversized.isInclude = false;
    for (int i = 0; i < 11; i++) {
        oversized.mutes.insert("mute" + std::to_string(i));
    }
    SecurityEventFilter oversizedFilter(oversized);
    Parcel oversizedParcel;
    (void)oversizedFilter.Marshalling(oversizedParcel);

    SecurityEventFilter reader;
    Parcel emptyParcel;
    (void)reader.ReadFromParcel(emptyParcel);

    Parcel onlyEventId;
    (void)onlyEventId.WriteInt64(1);
    (void)reader.ReadFromParcel(onlyEventId);

    Parcel noBool;
    (void)noBool.WriteInt64(1);
    (void)noBool.WriteInt64(2);
    (void)reader.ReadFromParcel(noBool);

    Parcel noSize;
    (void)noSize.WriteInt64(1);
    (void)noSize.WriteInt64(2);
    (void)noSize.WriteBool(true);
    (void)reader.ReadFromParcel(noSize);

    Parcel oversizedSize;
    (void)oversizedSize.WriteInt64(1);
    (void)oversizedSize.WriteInt64(2);
    (void)oversizedSize.WriteBool(true);
    (void)oversizedSize.WriteUint32(11);
    (void)reader.ReadFromParcel(oversizedSize);

    Parcel missingMute;
    (void)missingMute.WriteInt64(1);
    (void)missingMute.WriteInt64(2);
    (void)missingMute.WriteBool(true);
    (void)missingMute.WriteUint32(1);
    (void)reader.ReadFromParcel(missingMute);

    Parcel failedParcel;
    SecurityEventFilter *failed = SecurityEventFilter::Unmarshalling(failedParcel);
    delete failed;
}

void ReportRegionPolicyWhiteBoxTest()
{
    using namespace ::OHOS::Security::SecurityGuard;
    std::unordered_set<std::string> blockedFields;
    ReportRegionPolicy emptyPolicy;
    (void)emptyPolicy.LoadForCountry("");
    (void)emptyPolicy.GetBlockedFields(0x01C001101, blockedFields);
    (void)emptyPolicy.IsConfigValid();
    (void)emptyPolicy.GetVersion();

    ReportRegionPolicy filePolicy;
    (void)filePolicy.LoadForCountry("CN");

    const char *policyPath = "/data/service/el1/public/security_guard/report_region_policy.json";
    auto writeAndLoad = [](const std::string &path, const std::string &content) {
        std::ofstream ofs(path, std::ios::out | std::ios::trunc);
        if (!ofs.is_open()) {
            return;
        }
        ofs << content;
        ofs.close();
        ReportRegionPolicy policy;
        (void)policy.LoadForCountry("CN");
    };
    (void)mkdir("/data/service/el1/public/security_guard", 0755);
    writeAndLoad(policyPath, "");
    writeAndLoad(policyPath, std::string(1024 * 1024 + 1, 'a'));
    writeAndLoad(policyPath, "not-json");
    writeAndLoad(policyPath, "{}");
    writeAndLoad(policyPath,
        "{\"version\":\"v1\",\"policies\":{\"CN\":{\"0x01C001101\":{\"blockedFields\":[\"fieldA\"]}}}}");
    (void)unlink(policyPath);
    (void)mkdir(policyPath, 0755);
    {
        ReportRegionPolicy dirPolicy;
        (void)dirPolicy.LoadForCountry("CN");
    }
    (void)rmdir(policyPath);

    ReportRegionPolicy hitPolicy;
    hitPolicy.configValid_ = true;
    hitPolicy.cachedEventMap_["0x01C001101"].blockedFields = {"fieldA"};
    (void)hitPolicy.GetBlockedFields(0x01C001101, blockedFields);
    (void)hitPolicy.GetBlockedFields(0x02C001101, blockedFields);

    const char *cases[] = {
        "{\"policies\":{\"CN\":{}}}",
        "{\"version\":1,\"policies\":{\"CN\":{}}}",
        "{\"version\":\"v1\",\"policies\":{\"CN\":{}}}",
        "{}",
        "{\"policies\":[]}",
        "{\"policies\":{}}",
        "{\"policies\":{\"CN\":[]}}",
        "{\"policies\":{\"CN\":{\"e1\":1}}}",
        "{\"policies\":{\"CN\":{\"0x01C001101\":{}}}}",
        "{\"policies\":{\"CN\":{\"0x01C001101\":{\"blockedFields\":1}}}}",
        "{\"policies\":{\"CN\":{\"0x01C001101\":{\"blockedFields\":[1,\"fieldA\"]}}}}",
    };
    for (const char *json : cases) {
        cJSON *root = cJSON_Parse(json);
        if (root == nullptr) {
            continue;
        }
        ReportRegionPolicy policy;
        std::string version;
        std::unordered_map<std::string, EventFieldRule> eventMap;
        (void)policy.ParseCountryPolicy(root, "CN", version, eventMap);
        cJSON_Delete(root);
    }
}

void ReportRegionFilterWhiteBoxTest()
{
    using namespace ::OHOS::Security::SecurityGuard;
    ReportRegionFilter &filter = ReportRegionFilter::GetInstance();
    filter.Init();
    filter.Init();

    const char *filterPolicyPath = "/data/service/el1/public/security_guard/report_region_policy.json";
    (void)mkdir("/data/service/el1/public/security_guard", 0755);
    {
        std::ofstream ofs(filterPolicyPath, std::ios::out | std::ios::trunc);
        if (ofs.is_open()) {
            ofs << "{\"version\":\"v1\",\"policies\":{\"CN\":{}}}";
            ofs.close();
        }
    }
    filter.loaded_ = false;
    filter.Init();
    (void)filter.GetConfigMtime();
    (void)unlink(filterPolicyPath);

    filter.loaded_ = false;
    (void)filter.FilterContent(0x01C001101, "{\"fieldA\":1}");

    filter.loaded_ = true;
    filter.countryCodeValid_ = false;
    (void)filter.FilterContent(0x01C001101, "{\"fieldA\":1}");

    filter.countryCodeValid_ = true;
    filter.cachedCountryCode_ = "CN";
    filter.policy_.configValid_ = true;
    filter.policy_.cachedEventMap_["0x01C001101"].blockedFields = {"fieldA"};
    (void)filter.FilterContent(0x01C001101, "{\"fieldA\":1,\"fieldB\":2}");
    (void)filter.FilterContent(0x01C001101, "");
    (void)filter.FilterContent(0x02C001101, "{\"fieldA\":1}");

    std::unordered_set<std::string> fields = {"fieldA"};
    (void)filter.RemoveBlockedFields(0, "not-json", fields);
    (void)filter.RemoveBlockedFields(0, "[1,2]", fields);
    (void)filter.RemoveBlockedFields(0, "{\"fieldA\":1}", fields);
    (void)filter.RemoveBlockedFields(0, "{\"other\":1}", fields);

    (void)filter.QueryCountryCode();
    (void)filter.GetConfigMtime();
    (void)filter.IsCountryCodeExpired();

    filter.loaded_ = true;
    filter.countryCodeValid_ = true;
    filter.lastCountryCodeTime_ = std::chrono::steady_clock::now();
    filter.lastConfigMtime_ = 12345;
    filter.TryReloadIfChanged();

    filter.lastCountryCodeTime_ =
        std::chrono::steady_clock::now() - std::chrono::milliseconds(10 * 60 * 1000);
    (void)filter.IsCountryCodeExpired();
    filter.TryReloadIfChanged();
    filter.ReloadPolicy(0);
}
}  // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    OHOS::SecurityEventFilterWhiteBoxTest();
    OHOS::ReportRegionPolicyWhiteBoxTest();
    OHOS::ReportRegionFilterWhiteBoxTest();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    /* Run your code on date */
    OHOS::ReportSecurityInfoFuzzTest(fdp);
    OHOS::ReportSecurityInfoAsyncFuzzTest(fdp);
    OHOS::SecurityGuardConfigUpdateFuzzTest(fdp);
    return 0;
}
