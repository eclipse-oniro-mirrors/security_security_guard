/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "event_config.h"

#include "file_ex.h"

#include "config_data_manager.h"
#include "json_cfg.h"
#include "model_analysis_define.h"
#include "model_cfg_marshalling.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "config_define.h"
namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr const char *AUDIT_MODEL_ID = "3001000003";
    constexpr int32_t DB_MAX_VALUE = 100000;
    constexpr int32_t STORAGE_ROM_NUMS_MAX_VALUE = 1000;
}

bool EventConfig::Load(int mode)
{
    std::string path;
    if (mode == INIT_MODE) {
        if (FileExists(CONFIG_UPTATE_FILES[EVENT_CFG_INDEX])) {
            path = CONFIG_UPTATE_FILES[EVENT_CFG_INDEX];
        } else if (FileExists(CONFIG_PRESET_FILES[EVENT_CFG_INDEX])) {
            path = CONFIG_PRESET_FILES[EVENT_CFG_INDEX];
        }
    } else if (mode == UPDATE_MODE) {
        if (FileExists(CONFIG_CACHE_FILES[EVENT_CFG_INDEX])) {
            path = CONFIG_CACHE_FILES[EVENT_CFG_INDEX];
        }
    }
    SGLOGD("path=%{public}s", path.c_str());
    if (path.empty()) {
        SGLOGE("path is empty");
        return false;
    }
    stream_ = std::ifstream(path, std::ios::in);
    if (!stream_.is_open()) {
        SGLOGE("stream error, %{public}s", strerror(errno));
        return false;
    }
    return true;
}

bool EventConfig::Parse()
{
    if (!stream_.is_open()) {
        SGLOGE("stream error");
        return false;
    }
    nlohmann::json jsonObj = nlohmann::json::parse(stream_, nullptr, false);
    stream_.close();

    if (jsonObj.is_discarded()) {
        SGLOGI("json is discarded");
        return false;
    }

    std::vector<EventCfg> configs;
    bool success = EventConfig::ParseEventConfig(configs, jsonObj);
    if (!success) {
        SGLOGE("parse EventConfig error");
        return false;
    }
    EventConfig::CacheEventConfig(configs);
    EventConfig::CacheEventToTable(configs);
    SGLOGI("cache EventConfig success");
    return true;
}

bool EventConfig::Update()
{
    if (!stream_.is_open()) {
        SGLOGE("stream error");
        return false;
    }
    nlohmann::json jsonObj = nlohmann::json::parse(stream_, nullptr, false);
    stream_.close();

    if (jsonObj.is_discarded()) {
        SGLOGI("json is discarded");
        return false;
    }

    std::vector<EventCfg> configs;
    bool success = EventConfig::ParseEventConfig(configs, jsonObj);
    if (!success) {
        SGLOGE("parse EventConfig error");
        return false;
    }

    if (!SecurityGuardUtils::CopyFile(CONFIG_CACHE_FILES[EVENT_CFG_INDEX], CONFIG_UPTATE_FILES[EVENT_CFG_INDEX])) {
        SGLOGE("copyFile error");
        return false;
    }
    std::unordered_map<int64_t, EventCfg> newEventMap {};
    for (const auto &config : configs) {
        if (config.oldEventId != 0) {
            newEventMap[config.oldEventId] = config;
        }
        newEventMap[config.eventId] = config;
    }
    ConfigDataManager::GetInstance().SwapEventConfigMap(std::move(newEventMap));
    EventConfig::CacheEventToTable(configs);
    SGLOGI("cache EventConfig success");
    return true;
}

bool EventConfig::ParseEventConfig(std::vector<EventCfg> &configs, nlohmann::json &jsonObj)
{
    bool success = JsonCfg::Unmarshal<EventCfg>(configs, jsonObj, EVENT_CFG_KEY);
    if (success) {
        for (EventCfg &config : configs) {
            uint32_t maxValue = STORAGE_ROM_NUMS_MAX_VALUE;
            if (!config.owner.empty() && config.owner.at(0) == AUDIT_MODEL_ID) {
                maxValue = DB_MAX_VALUE;
            }
            if (config.storageRomNums >= maxValue) {
                config.storageRomNums = maxValue;
            }
        }
    }
    return success;
}

void EventConfig::CacheEventConfig(const std::vector<EventCfg> &configs)
{
    for (const EventCfg &config : configs) {
        if (config.oldEventId != 0) {
            ConfigDataManager::GetInstance().InsertEventMap(config.oldEventId, config);
        }
        ConfigDataManager::GetInstance().InsertEventMap(config.eventId, config);
    }
}

void EventConfig::CacheEventToTable(const std::vector<EventCfg> &configs)
{
    for (const EventCfg &config : configs) {
        if (config.oldEventId != 0) {
            ConfigDataManager::GetInstance().InsertEventToTableMap(config.oldEventId, config.dbTable);
        }
        ConfigDataManager::GetInstance().InsertEventToTableMap(config.eventId, config.dbTable);
    }
}
} // OHOS::Security::SecurityGuard
