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

#include "config_data_manager_fuzzer.h"

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
bool ConfigDataManagerFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int64_t eventId = fdp.ConsumeIntegral<int64_t>();
    uint32_t modelId = fdp.ConsumeIntegral<uint32_t>();
    std::string table = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    std::set<int64_t> eventIds{eventId};
    ModelCfg modelCfg = {};
    EventCfg eventCfg = {};
    ConfigDataManager::GetInstance().InsertModelMap(modelId, modelCfg);
    ConfigDataManager::GetInstance().InsertEventMap(eventId, eventCfg);
    ConfigDataManager::GetInstance().InsertModelToEventMap(modelId, eventIds);
    ConfigDataManager::GetInstance().InsertEventToTableMap(eventId, table);
    ConfigDataManager::GetInstance().GetEventIds(modelId);
    ConfigDataManager::GetInstance().GetAllEventIds();
    ConfigDataManager::GetInstance().GetAllModelIds();
    ConfigDataManager::GetInstance().GetModelConfig(modelId, modelCfg);
    ConfigDataManager::GetInstance().GetEventConfig(eventId, eventCfg);
    ConfigDataManager::GetInstance().GetTableFromEventId(eventId);
    ConfigDataManager::GetInstance().ResetModelMap();
    ConfigDataManager::GetInstance().ResetEventMap();
    ConfigDataManager::GetInstance().ResetModelToEventMap();
    ConfigDataManager::GetInstance().ResetEventToTableMap();
    std::unordered_map<int64_t, EventCfg> mapTmp {};
    ConfigDataManager::GetInstance().SwapEventConfigMap(mapTmp);
    return true;
}

bool EventConfigFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    ConfigManager::GetInstance().StartUpdate();
    int mode = fdp.ConsumeIntegral<int32_t>();
    EventConfig config{};
    nlohmann::json jsonObj;
    EventCfg cfg{};
    std::vector<EventCfg> cfgs{cfg};
    config.Load(mode);
    config.Parse();
    config.Update();
    config.ParseEventConfig(cfgs, jsonObj);
    config.CacheEventConfig(cfgs);
    config.CacheEventToTable(cfgs);
    return true;
}

}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    OHOS::ConfigDataManagerFuzzTest(data, size);
    OHOS::EventConfigFuzzTest(data, size);
    return 0;
}
