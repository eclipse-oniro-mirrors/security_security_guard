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

#ifndef SECURITY_GUARD_CONFIG_DATA_MANAGER_MOCK_H
#define SECURITY_GUARD_CONFIG_DATA_MANAGER_MOCK_H

#include "security_event_info.h"
#include "i_model_info.h"

namespace OHOS::Security::SecurityGuard {
class ConfigDataManager {
public:
    static ConfigDataManager &GetInstance();
    void InsertModelMap(uint32_t modelId, const ModelCfg &config) {};
    void InsertEventMap(int64_t eventId, const EventCfg &config) {};
    void InsertModelToEventMap(uint32_t modelId, std::set<int64_t> eventIds) {};
    void InsertEventToTableMap(int64_t eventId, std::string table) {};
    void InsertEventGroupMap(const std::unordered_map<std::string, EventGroupCfg> &eventGroupMap) {};
    bool GetIsBatchUpload(const std::string &groupName)
    {
        return true;
    }
    bool GetEventGroupConfig(const std::string &groupName, EventGroupCfg &config)
    {
        config.eventList.insert(1);
        return true;
    }
    void ResetModelMap() {};
    void ResetEventMap() {};
    void SwapEventConfigMap(std::unordered_map<int64_t, EventCfg> newEventMap) {}
    void ResetModelToEventMap() {};
    void ResetEventToTableMap() {};
    std::vector<int64_t> GetEventIds(uint32_t modelId)
    {
        std::vector<int64_t> ret {};
        ret.emplace_back(1);
        return ret;
    }
    std::vector<int64_t> GetAllEventIds()
    {
        std::vector<int64_t> ret {};
        ret.emplace_back(1);
        return ret;
    }
    std::vector<uint32_t> GetAllModelIds()
    {
        std::vector<uint32_t> ret {};
        ret.emplace_back(1);
        return ret;
    }
    std::vector<EventCfg> GetAllEventConfigs()
    {
        EventCfg cfg {};
        cfg.eventId = 1;
        std::vector<EventCfg> ret {};
        ret.emplace_back(cfg);
        return ret;
    }
    bool GetModelConfig(uint32_t modelId, ModelCfg &config)
    {
        return true;
    }
    bool GetEventConfig(int64_t eventId, EventCfg &config)
    {
        config.eventType = static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL);
        return true;
    }
    std::string GetTableFromEventId(int64_t eventId)
    {
        return "risk_event";
    }
private:
};
} // OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_CONFIG_DATA_MANAGER_MOCK_H