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

#include "config_data_manager.h"

#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
void ConfigDataManager::InsertModelMap(uint32_t modelId, const ModelCfg &config)
{
    std::lock_guard<std::mutex> lock(modelMutex_);
    modelMap_[modelId] = config;
}

void ConfigDataManager::InsertEventMap(int64_t eventId, const EventCfg &config)
{
    std::lock_guard<std::mutex> lock(eventMutex_);
    eventMap_[eventId] = config;
}

void ConfigDataManager::InsertModelToEventMap(uint32_t modelId, std::set<int64_t> eventIds)
{
    std::lock_guard<std::mutex> lock(modelToEventMutex_);
    modelToEventMap_[modelId] = eventIds;
}

void ConfigDataManager::InsertEventToTableMap(int64_t eventId, std::string table)
{
    std::lock_guard<std::mutex> lock(eventToTableMutex_);
    eventToTableMap_[eventId] = table;
}

void ConfigDataManager::ResetModelMap()
{
    std::lock_guard<std::mutex> lock(modelMutex_);
    modelMap_.clear();
}

void ConfigDataManager::ResetEventMap()
{
    std::lock_guard<std::mutex> lock(eventMutex_);
    eventMap_.clear();
}

void ConfigDataManager::ResetModelToEventMap()
{
    std::lock_guard<std::mutex> lock(modelToEventMutex_);
    modelToEventMap_.clear();
}

void ConfigDataManager::ResetEventToTableMap()
{
    std::lock_guard<std::mutex> lock(eventToTableMutex_);
    eventToTableMap_.clear();
}

std::vector<int64_t> ConfigDataManager::GetEventIds(uint32_t modelId)
{
    SGLOGD("modelId=%{public}u", modelId);
    std::lock_guard<std::mutex> lock(modelToEventMutex_);
    std::vector<int64_t> vector;
    if (modelToEventMap_.find(modelId) != modelToEventMap_.end()) {
        SGLOGD("map contains modelId=%{public}u", modelId);
        vector.assign(modelToEventMap_[modelId].begin(), modelToEventMap_[modelId].end());
    }
    return vector;
}

std::vector<int64_t> ConfigDataManager::GetAllEventIds()
{
    std::lock_guard<std::mutex> lock(eventMutex_);
    std::vector<int64_t> vector;
    for (const auto &entry : eventMap_) {
        SGLOGD("eventId=%{public}" PRId64 "", entry.first);
        vector.emplace_back(entry.first);
    }
    return vector;
}

std::vector<uint32_t> ConfigDataManager::GetAllModelIds()
{
    std::lock_guard<std::mutex> lock(modelMutex_);
    std::vector<uint32_t> vector;
    for (const auto &entry : modelMap_) {
        SGLOGD("modelId=%{public}u", entry.first);
        vector.emplace_back(entry.first);
    }
    return vector;
}

bool ConfigDataManager::GetModelConfig(uint32_t modelId, ModelCfg &config)
{
    std::lock_guard<std::mutex> lock(modelMutex_);
    auto it = modelMap_.find(modelId);
    if (it != modelMap_.end()) {
        config = it->second;
        return true;
    }
    return false;
}

bool ConfigDataManager::GetEventConfig(int64_t eventId, EventCfg &config)
{
    std::lock_guard<std::mutex> lock(eventMutex_);
    auto it = eventMap_.find(eventId);
    if (it != eventMap_.end()) {
        config = it->second;
        return true;
    }
    return false;
}

std::string ConfigDataManager::GetTableFromEventId(int64_t eventId)
{
    std::lock_guard<std::mutex> lock(eventToTableMutex_);
    return eventToTableMap_[eventId];
}
} // OHOS::Security::SecurityGuard