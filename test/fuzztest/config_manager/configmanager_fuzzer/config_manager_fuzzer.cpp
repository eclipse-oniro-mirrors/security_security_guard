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

#include "config_manager_fuzzer.h"

#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "securec.h"

#define private public
#define protected public
#include "base_config.h"
#include "config_data_manager.h"
#include "i_model_info.h"
#include "config_manager.h"
#include "config_operator.h"
#include "config_subscriber.h"
#include "event_config.h"
#include "json_cfg.h"
#include "security_guard_utils.h"
#include "model_analysis_define.h"
#include "model_cfg_marshalling.h"
#include "model_config.h"
#include "security_guard_log.h"
#undef private
#undef protected

using namespace OHOS::Security::SecurityGuard;
namespace {
    constexpr int MAX_STRING_SIZE = 1024;
}
namespace OHOS {
bool ModelConfigFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int mode = fdp.ConsumeIntegral<int32_t>();
    ModelConfig config{};
    nlohmann::json jsonObj;
    ModelCfg cfg = {};
    std::vector<ModelCfg> cfgs{cfg};
    config.Load(mode);
    config.Parse();
    config.Update();
    config.ParseModelConfig(cfgs, jsonObj);
    config.CacheModelConfig(cfgs);
    return true;
}

void JsonConfigFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    uint64_t uint64 = fdp.ConsumeIntegral<uint64_t>();
    int64_t int64 = fdp.ConsumeIntegral<int64_t>();
    int32_t int32 = fdp.ConsumeIntegral<int32_t>();
    std::string string = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    std::vector<int32_t> vec32;
    std::vector<int64_t> vec64;
    nlohmann::json jsonObj {
        { string, uint64 }
    };
    JsonCfg::Unmarshal(uint64, jsonObj, string);
    nlohmann::json jsonObj1 {
        { string, int64 }
    };
    JsonCfg::Unmarshal(int64, jsonObj1, string);
    nlohmann::json jsonObj2 {
        { string, {int32} }
    };
    JsonCfg::Unmarshal(vec32, jsonObj2, string);
    nlohmann::json jsonObj3 {
        { string, {int64} }
    };
    JsonCfg::Unmarshal(vec64, jsonObj3, string);
}

void SecurityGuardUtilsFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int64_t int64 = fdp.ConsumeIntegral<int64_t>();
    uint32_t uint32 = fdp.ConsumeIntegral<uint32_t>();
    std::string string = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    unsigned long long value = 0;
    SecurityGuardUtils::StrToU32(string, uint32);
    SecurityGuardUtils::StrToI64(string, int64);
    SecurityGuardUtils::StrToULL(string, value);
    SecurityGuardUtils::CopyFile(string, string);
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    OHOS::ModelConfigFuzzTest(data, size);
    OHOS::JsonConfigFuzzTest(data, size);
    OHOS::SecurityGuardUtilsFuzzTest(data, size);
    return 0;
}
