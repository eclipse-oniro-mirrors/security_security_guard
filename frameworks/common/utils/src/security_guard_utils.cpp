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

#include "security_guard_utils.h"

#include <cerrno>
#include <fstream>

#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr int32_t DEC_RADIX = 10;
    constexpr int32_t HEX_RADIX = 16;
    constexpr int32_t STR_INDEX = 2;
    constexpr int32_t TIME_BUF_LEN = 32;
    constexpr int32_t FILE_MAX_SIZE = 2 * 1024 * 1024; // byte
}

bool SecurityGuardUtils::StrToU32(const std::string &str, uint32_t &value)
{
    unsigned long long tmp = 0;
    bool isOK = StrToULL(str, tmp);
    value = static_cast<uint32_t>(tmp);
    return isOK && (tmp <= UINT32_MAX);
}

bool SecurityGuardUtils::StrToI64(const std::string &str, int64_t &value)
{
    long long tmp = 0;
    bool isOK = StrToLL(str, tmp, DEC_RADIX);
    value = tmp;
    return isOK && (tmp >= INT64_MIN && tmp <= INT64_MAX);
}

bool SecurityGuardUtils::StrToI64Hex(const std::string &str, int64_t &value)
{
    long long tmp = 0;
    bool isOK;
    if (str.substr(0, STR_INDEX) == "0x") {
        isOK = StrToLL(str, tmp, HEX_RADIX);
    } else {
        isOK = StrToLL(str, tmp, DEC_RADIX);
    }
    value = tmp;
    return isOK && (tmp >= INT64_MIN && tmp <= INT64_MAX);
}

bool SecurityGuardUtils::StrToLL(const std::string &str, long long &value, int32_t base)
{
    if (str.empty()) {
        return false;
    }
    auto add = str.c_str();
    char *end = nullptr;
    errno = 0;
    value = strtoll(add, &end, base);
    if ((errno == ERANGE && (value == LLONG_MAX || value == LLONG_MIN)) || (errno != 0 && value == 0)) {
        SGLOGE("strtoll converse error,str=%{public}s", str.c_str());
        return false;
    }
    if (end == add) {
        SGLOGE("strtoll no digit find");
        return false;
    }
    if (end[0] != '\0') {
        SGLOGE("strtoll no all digit");
        return false;
    }

    return true;
}

bool SecurityGuardUtils::StrToULL(const std::string &str, unsigned long long &value)
{
    if (str.empty()) {
        return false;
    }
    auto add = str.c_str();
    char *end = nullptr;
    errno = 0;
    value = strtoull(add, &end, DEC_RADIX);
    if ((errno == ERANGE && value == ULLONG_MAX) || (errno != 0 && value == 0)) {
        SGLOGE("strtoull converse error,str=%{public}s", str.c_str());
        return false;
    }
    if (end == add) {
        SGLOGE("strtoull no digit find");
        return false;
    }
    if (end[0] != '\0') {
        SGLOGE("strtoull no all digit");
        return false;
    }

    return true;
}

std::string SecurityGuardUtils::GetDate()
{
    time_t timestamp = time(nullptr);
    struct tm timeInfo{};
    localtime_r(&timestamp, &timeInfo);
    char buf[TIME_BUF_LEN] = {};
    if (strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", &timeInfo) == 0) {
        return "";
    }
    std::string data(buf);
    return data;
}

bool SecurityGuardUtils::CopyFile(const std::string &srcPath, const std::string &dstPath)
{
    std::ifstream src(srcPath, std::ios::binary);
    if (!src.is_open()) {
        SGLOGE("copy file stream error");
        return false;
    }
    if (src.seekg(0, std::ios_base::end).tellg() > FILE_MAX_SIZE) {
        SGLOGE("cfg file is too large");
        src.close();
        return false;
    }
    src.seekg(0, std::ios::beg);
    std::ofstream dst(dstPath, std::ios::binary);
    if (!dst.is_open()) {
        SGLOGE("copy file stream error");
        src.close();
        return false;
    }

    dst << src.rdbuf();
    src.close();
    dst.close();
    return true;
}
}