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

#include "model_config.h"

#include "file_ex.h"

#include "config_data_manager.h"
#include "json_cfg.h"
#include "model_analysis_define.h"
#include "model_cfg_marshalling.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "config_define.h"

namespace OHOS::Security::SecurityGuard {
bool ModelConfig::Load(int mode)
{
    std::string path;
    if (mode == INIT_MODE) {
        if (FileExists(CONFIG_UPTATE_FILES[MODEL_CFG_INDEX])) {
            path = CONFIG_UPTATE_FILES[MODEL_CFG_INDEX];
        } else if (FileExists(CONFIG_PRESET_FILES[MODEL_CFG_INDEX])) {
            path = CONFIG_PRESET_FILES[MODEL_CFG_INDEX];
        }
    } else if (mode == UPDATE_MODE) {
        if (FileExists(CONFIG_CACHE_FILES[MODEL_CFG_INDEX])) {
            path = CONFIG_CACHE_FILES[MODEL_CFG_INDEX];
        }
    }
    SGLOGD("path=%{private}s", path.c_str());
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

bool ModelConfig::Parse()
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

    std::vector<ModelCfg> configs;
    bool success = ParseModelConfig(configs, jsonObj);
    if (!success) {
        SGLOGE("parse ModelConfig error");
        return false;
    }
    CacheModelConfig(configs);
    CacheModelToEvent(configs);
    SGLOGI("cache ModelConfig success");
    return true;
}

bool ModelConfig::Update()
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

    std::vector<ModelCfg> configs;
    bool success = ParseModelConfig(configs, jsonObj);
    if (!success) {
        SGLOGE("parse EventConfig error");
        return false;
    }

    if (!SecurityGuardUtils::CopyFile(CONFIG_CACHE_FILES[MODEL_CFG_INDEX], CONFIG_UPTATE_FILES[MODEL_CFG_INDEX])) {
        SGLOGE("copyFile error");
        return false;
    }
    ConfigDataManager::GetInstance().ResetModelMap();
    CacheModelConfig(configs);
    CacheModelToEvent(configs);
    SGLOGI("cache ModelConfig success");
    return true;
}

bool ModelConfig::ParseModelConfig(std::vector<ModelCfg> &configs, nlohmann::json &jsonObj)
{
    return JsonCfg::Unmarshal<ModelCfg>(configs, jsonObj, MODEL_CFG_KEY);
};

void ModelConfig::CacheModelConfig(const std::vector<ModelCfg> &configs)
{
    for (const ModelCfg &config : configs) {
        SGLOGD("modelId=%{public}u", config.modelId);
        ConfigDataManager::GetInstance().InsertModelMap(config.modelId, config);
    }
}

void ModelConfig::CacheModelToEvent(const std::vector<ModelCfg> &configs)
{
    for (const ModelCfg &config : configs) {
        SGLOGD("modelId=%{public}u", config.modelId);
        std::set<int64_t> set;
        for (int64_t event : config.eventList) {
            set.emplace(event);
        }
        ConfigDataManager::GetInstance().InsertModelToEventMap(config.modelId, set);
    }
}
} // OHOS::Security::SecurityGuard