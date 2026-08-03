/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "event_group_config.h"

#include "file_ex.h"
#include "config_data_manager.h"
#include "json_cfg.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "config_define.h"
namespace OHOS::Security::SecurityGuard {
bool EventGroupConfig::Load(int mode)
{
    std::string path;
    if (mode == INIT_MODE) {
        if (FileExists(CONFIG_PRESET_FILES[EVENT_GROUP_CFG_INDEX])) {
            path = CONFIG_PRESET_FILES[EVENT_GROUP_CFG_INDEX];
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

bool EventGroupConfig::Parse()
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

    bool success = ParseEventGroupConfig(jsonObj);
    if (!success) {
        SGLOGE("parse EventGroupConfig error");
        return false;
    }
    return true;
}

bool EventGroupConfig::Update()
{
    return true;
}

bool EventGroupConfig::ParseEventGroupConfig(const nlohmann::json &jsonObj)
{
    if (jsonObj.find("eventGroupList") == jsonObj.end() || !jsonObj.at("eventGroupList").is_array()) {
        SGLOGE("not find eventGroupList or type err");
        return false;
    }
    std::unordered_map<std::string, EventGroupCfg> eventGroupMap;
    for (const auto &iter : jsonObj["eventGroupList"]) {
        if (!iter.is_object()) {
            return false;
        }
        std::vector<std::string> eventList;
        EventGroupCfg cfg {};
        if (!JsonCfg::Unmarshal(cfg.eventGroupName, iter, "eventGroupName") || cfg.eventGroupName == "") {
            SGLOGE("fail to parse eventGroupName");
            return false;
        }
        if (!JsonCfg::Unmarshal(eventList, iter, "eventList")) {
            SGLOGE("fail to parse eventList");
            return false;
        }
        for (const auto &event : eventList) {
            int64_t tmp = 0;
            if (event == "" || !SecurityGuardUtils::StrToI64Hex(event, tmp)) {
                continue;
            }
            cfg.eventList.insert(tmp);
        }
        std::vector<std::string> permissonList;
        if (!JsonCfg::Unmarshal(permissonList, iter, "permission")) {
            SGLOGE("fail to parse permission");
            return false;
        }
        for (const auto &it : permissonList) {
            cfg.permissionList.insert(it);
        }
        int32_t isBatchUpload = 0;
        if (!JsonCfg::Unmarshal(isBatchUpload, iter, "isBatchUpload")) {
            SGLOGE("fail to parse isBatchUpload");
            return false;
        }
        cfg.isBatchUpload = isBatchUpload;
        eventGroupMap[cfg.eventGroupName] = cfg;
    }
    ConfigDataManager::GetInstance().InsertEventGroupMap(eventGroupMap);
    return true;
}

} // OHOS::Security::SecurityGuard
