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

#include "model_cfg_marshalling.h"

#include "json_cfg.h"
#include "model_analysis_define.h"
#include "security_guard_utils.h"

namespace OHOS::Security::SecurityGuard {
using nlohmann::json;

void from_json(const nlohmann::json &jsonObj, AppDetectionCfg &config)
{
    if (jsonObj.find("detectionCategory") == jsonObj.end()) {
        return;
    }

    if (!jsonObj.at("detectionCategory").is_string()) {
        return;
    }

    config.detectionCategory = jsonObj.at("detectionCategory").get<std::string>();
}

void from_json(const nlohmann::json &jsonObj, Field &field)
{
    if (jsonObj.find("fieldName") == jsonObj.end() || jsonObj.find("fieldType") == jsonObj.end() ||
        jsonObj.find("value") == jsonObj.end()) {
        return;
    }

    if (!jsonObj.at("fieldName").is_string() || !jsonObj.at("fieldType").is_string() ||
        !jsonObj.at("value").is_string()) {
        return;
    }

    field.fieldName = jsonObj.at("fieldName").get<std::string>();
    field.fieldType = jsonObj.at("fieldType").get<std::string>();
    field.value = jsonObj.at("value").get<std::string>();
}

void from_json(const nlohmann::json &jsonObj, Rule &rule)
{
    if (jsonObj.find("eventId") == jsonObj.end() || jsonObj.find("fields") == jsonObj.end() ||
        jsonObj.find("fieldsRelation") == jsonObj.end()) {
        return;
    }

    if (!jsonObj.at("eventId").is_number() || !jsonObj.at("fields").is_array() ||
        !jsonObj.at("fieldsRelation").is_string()) {
        return;
    }

    rule.eventId = jsonObj.at("eventId").get<int64_t>();
    rule.fields = jsonObj.at("fields").get<std::vector<Field>>();
    rule.fieldsRelation = jsonObj.at("fieldsRelation").get<std::string>();
}

void from_json(const nlohmann::json &jsonObj, BuildInDetectionCfg &config)
{
    if (jsonObj.find("rules") == jsonObj.end() || jsonObj.find("rulesRelation") == jsonObj.end() ||
        jsonObj.find("trueResult") == jsonObj.end() || jsonObj.find("falseResult") == jsonObj.end()) {
        return;
    }

    if (!jsonObj.at("rules").is_array() || !jsonObj.at("rulesRelation").is_string() ||
        !jsonObj.at("trueResult").is_string() || !jsonObj.at("falseResult").is_string()) {
        return;
    }

    config.rules = jsonObj.at("rules").get<std::vector<Rule>>();
    config.rulesRelation = jsonObj.at("rulesRelation").get<std::string>();
    config.trueResult = jsonObj.at("trueResult").get<std::string>();
    config.falseResult = jsonObj.at("falseResult").get<std::string>();
}

void to_json(json &jsonObj, const ModelCfg &modelCfg)
{
    std::vector<std::string> preLoads;
    std::transform(modelCfg.preload.begin(), modelCfg.preload.end(),
        std::back_inserter(preLoads), [] (int64_t eventId) {
        return std::to_string(eventId);
    });

    std::vector<std::string> eventList;
    std::transform(modelCfg.eventList.begin(), modelCfg.eventList.end(),
        std::back_inserter(eventList), [] (int64_t eventId) {
        return std::to_string(eventId);
    });

    jsonObj = json {
        { MODEL_CFG_MODEL_ID_KEY, std::to_string(modelCfg.modelId) },
        { MODEL_CFG_PATH_KEY, modelCfg.path },
        { MODEL_CFG_FORMAT_KEY, modelCfg.format },
        { MODEL_CFG_START_MODE_KEY, modelCfg.startMode },
        { MODEL_CFG_PRELOAD_KEY, preLoads },
        { MODEL_CFG_EVENT_LIST_KEY, eventList },
        { MODEL_CFG_PERMISSIONS_KEY, modelCfg.permissions },
        { MODEL_CFG_DB_TABLE_KEY, modelCfg.dbTable },
        { MODEL_CFG_RUNNING_CNTL_KEY, modelCfg.runningCntl },
        { MODEL_CFG_CALLER_KEY, modelCfg.caller }
    };
}

void from_json(const json &jsonObj, ModelCfg &modelCfg)
{
    std::string modelId;
    JsonCfg::Unmarshal(modelId, jsonObj, MODEL_CFG_MODEL_ID_KEY);
    uint32_t value = 0;
    if (!SecurityGuardUtils::StrToU32(modelId, value)) {
        return;
    }
    modelCfg.modelId = value;
    JsonCfg::Unmarshal(modelCfg.path, jsonObj, MODEL_CFG_PATH_KEY);
    JsonCfg::Unmarshal(modelCfg.format, jsonObj, MODEL_CFG_FORMAT_KEY);
    JsonCfg::Unmarshal(modelCfg.startMode, jsonObj, MODEL_CFG_START_MODE_KEY);

    std::vector<std::string> preLoads;
    JsonCfg::Unmarshal(preLoads, jsonObj, MODEL_CFG_PRELOAD_KEY);
    for (const std::string& eventId : preLoads) {
        int64_t tmp = 0;
        if (eventId == "" || !SecurityGuardUtils::StrToI64(eventId, tmp)) {
            continue;
        }
        modelCfg.preload.emplace_back(tmp);
    }

    std::vector<std::string> eventList;
    JsonCfg::Unmarshal(eventList, jsonObj, MODEL_CFG_EVENT_LIST_KEY);
    for (const std::string& eventId : eventList) {
        int64_t tmp = 0;
        if (eventId == "" || !SecurityGuardUtils::StrToI64(eventId, tmp)) {
            continue;
        }
        modelCfg.eventList.emplace_back(tmp);
    }
    JsonCfg::Unmarshal(modelCfg.permissions, jsonObj, MODEL_CFG_PERMISSIONS_KEY);
    JsonCfg::Unmarshal(modelCfg.dbTable, jsonObj, MODEL_CFG_DB_TABLE_KEY);
    JsonCfg::Unmarshal(modelCfg.runningCntl, jsonObj, MODEL_CFG_RUNNING_CNTL_KEY);
    JsonCfg::Unmarshal(modelCfg.caller, jsonObj, MODEL_CFG_CALLER_KEY);
    JsonCfg::Unmarshal(modelCfg.type, jsonObj, MODEL_CFG_TYPE_KEY);
    JsonCfg::Unmarshal(modelCfg.config, jsonObj, MODEL_CFG_BUILD_IN_CFG_KEY);
    JsonCfg::Unmarshal(modelCfg.appDetectionConfig, jsonObj, MODEL_CFG_APP_DETECTION_CFG_KEY);
}

void to_json(json &jsonObj, const EventCfg &eventCfg)
{
    jsonObj = json {
        { EVENT_CFG_EVENT_ID_KEY, std::to_string(eventCfg.eventId) },
        { EVENT_CFG_EVENT_NAME_KEY, eventCfg.eventName },
        { EVENT_CFG_VERSION_KEY, eventCfg.version },
        { EVENT_CFG_EVENT_TYPE_KEY, eventCfg.eventType },
        { EVENT_CFG_DATA_SENSITIVITY_LEVEL_KEY, eventCfg.dataSensitivityLevel },
        { EVENT_CFG_DISCARD_EVENT_WHITELIST_KEY, eventCfg.discardEventWhiteList },
        { EVENT_CFG_STORAGE_RAM_NUM_KEY, eventCfg.storageRamNums },
        { EVENT_CFG_STORAGE_ROM_NUM_KEY, eventCfg.storageRomNums },
        { EVENT_CFG_STORAGE_TIME_KEY, eventCfg.storageTime },
        { EVENT_CFG_OWNER_KEY, eventCfg.owner },
        { EVENT_CFG_SOURCE_KEY, eventCfg.source },
        { EVENT_CFG_DB_TABLE_KEY, eventCfg.dbTable },
        { EVENT_CFG_PROG_KEY, eventCfg.prog},
        { EVENT_CFG_BATCH_UPLOAD_KEY, eventCfg.isBatchUpload },
        { EVENT_CFG_IS_STICKY_KEY, eventCfg.isSticky },
        { EVENT_CFG_SERVICE_ID_KEY, eventCfg.serviceId }
    };
}

void from_json(const json &jsonObj, EventCfg &eventCfg)
{
    std::string eventId;
    JsonCfg::Unmarshal(eventId, jsonObj, EVENT_CFG_EVENT_ID_KEY);
    int64_t value = 0;
    if (!SecurityGuardUtils::StrToI64Hex(eventId, value)) {
        return;
    }
    eventCfg.eventId = value;
    value = 0;
    eventId = {};
    JsonCfg::Unmarshal(eventId, jsonObj, EVENT_CFG_OLD_EVENT_ID_KEY);
    if (!SecurityGuardUtils::StrToI64Hex(eventId, value)) {
        value = 0;
    }
    eventCfg.oldEventId = value;
    JsonCfg::Unmarshal(eventCfg.eventName, jsonObj, EVENT_CFG_EVENT_NAME_KEY);
    JsonCfg::Unmarshal(eventCfg.version, jsonObj, EVENT_CFG_VERSION_KEY);
    JsonCfg::Unmarshal(eventCfg.eventType, jsonObj, EVENT_CFG_EVENT_TYPE_KEY);
    JsonCfg::Unmarshal(eventCfg.collectOnStart, jsonObj, EVENT_CFG_COLLECT_ON_START_KEY);
    JsonCfg::Unmarshal(eventCfg.dataSensitivityLevel, jsonObj, EVENT_CFG_DATA_SENSITIVITY_LEVEL_KEY);
    JsonCfg::Unmarshal(eventCfg.discardEventWhiteList, jsonObj, EVENT_CFG_DISCARD_EVENT_WHITELIST_KEY);
    JsonCfg::Unmarshal(eventCfg.storageRamNums, jsonObj, EVENT_CFG_STORAGE_RAM_NUM_KEY);
    JsonCfg::Unmarshal(eventCfg.storageRomNums, jsonObj, EVENT_CFG_STORAGE_ROM_NUM_KEY);
    JsonCfg::Unmarshal(eventCfg.storageTime, jsonObj, EVENT_CFG_STORAGE_TIME_KEY);
    JsonCfg::Unmarshal(eventCfg.owner, jsonObj, EVENT_CFG_OWNER_KEY);
    JsonCfg::Unmarshal(eventCfg.source, jsonObj, EVENT_CFG_SOURCE_KEY);
    JsonCfg::Unmarshal(eventCfg.dbTable, jsonObj, EVENT_CFG_DB_TABLE_KEY);
    JsonCfg::Unmarshal(eventCfg.prog, jsonObj, EVENT_CFG_PROG_KEY);
    JsonCfg::Unmarshal(eventCfg.isBatchUpload, jsonObj, EVENT_CFG_BATCH_UPLOAD_KEY);
    JsonCfg::Unmarshal(eventCfg.isSticky, jsonObj, EVENT_CFG_IS_STICKY_KEY);
    JsonCfg::Unmarshal(eventCfg.serviceId, jsonObj, EVENT_CFG_SERVICE_ID_KEY);
}

void to_json(json &jsonObj, const DataMgrCfgSt &dataMgrCfg)
{
    jsonObj = json {
        { DATA_MGR_DEVICE_RAM_KEY, dataMgrCfg.deviceRam },
        { DATA_MGR_DEVICE_ROM_KEY, dataMgrCfg.deviceRom },
        { DATA_MGR_EVENT_MAX_RAM_NUM_KEY, dataMgrCfg.eventMaxRamNum },
        { DATA_MGR_EVENT_MAX_ROM_NUM_KEY, dataMgrCfg.eventMaxRomNum }
    };
}

void from_json(const json &jsonObj, DataMgrCfgSt &dataMgrCfg)
{
    JsonCfg::Unmarshal(dataMgrCfg.deviceRam, jsonObj, DATA_MGR_DEVICE_RAM_KEY);
    JsonCfg::Unmarshal(dataMgrCfg.deviceRom, jsonObj, DATA_MGR_DEVICE_ROM_KEY);
    JsonCfg::Unmarshal(dataMgrCfg.eventMaxRamNum, jsonObj, DATA_MGR_EVENT_MAX_RAM_NUM_KEY);
    JsonCfg::Unmarshal(dataMgrCfg.eventMaxRomNum, jsonObj, DATA_MGR_EVENT_MAX_ROM_NUM_KEY);
}

void to_json(json &jsonObj, const SecEvent &eventDataSt)
{
    jsonObj = json {
        { EVENT_DATA_EVENT_ID_KEY, eventDataSt.eventId },
        { EVENT_DATA_VERSION_KEY, eventDataSt.version },
        { EVENT_DATA_DATE_KEY, eventDataSt.date },
        { EVENT_DATA_EVENT_CONTENT_KEY, eventDataSt.content },
        { EVENT_CFG_USER_ID_KEY, eventDataSt.userId },
        { EVENT_CFG_DEVICE_ID_KEY, eventDataSt.deviceId },
    };
}

void to_json(json &jsonObj, const EventContentSt &eventContentSt)
{
    jsonObj = json {
        { EVENT_CONTENT_STATUS_KEY, eventContentSt.status },
        { EVENT_CONTENT_CRED_KEY, eventContentSt.cred },
        { EVENT_CONTENT_EXTRA_KEY, eventContentSt.extra }
    };
}

void from_json(const json &jsonObj, EventContentSt &eventContentSt)
{
    (void)JsonCfg::Unmarshal(eventContentSt.status, jsonObj, EVENT_CONTENT_STATUS_KEY);
    (void)JsonCfg::Unmarshal(eventContentSt.cred, jsonObj, EVENT_CONTENT_CRED_KEY);
    (void)JsonCfg::Unmarshal(eventContentSt.extra, jsonObj, EVENT_CONTENT_EXTRA_KEY);
}
}