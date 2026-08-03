/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <thread>
#include <chrono>
#include <cinttypes>

#include "file_util.h"
#include "json_util.h"
#include "security_guard_utils.h"
#include "data_collect_manager.h"
#include "ffrt.h"
#include "directory_ex.h"
#include "detect_plugin_manager.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr int32_t MAX_RETRY_INTERVAL = 60;
    constexpr int32_t RETRY_INTERVAL_INCREMENT = 10;
    constexpr int32_t MAX_PLUGIN_SIZE = 20;
    constexpr const char *PLUGIN_PREFIX_PATH = "/system/lib64/";
}

DetectPluginManager& DetectPluginManager::getInstance()
{
    static DetectPluginManager instance;
    return instance;
}

void DetectPluginManager::LoadAllPlugins(const std::string &fileName)
{
    SGLOGI("Start LoadAllPlugins.");
    if (!ParsePluginConfig(fileName)) {
        return;
    }
    for (const auto &plugin : plugins_) {
        LoadPlugin(plugin);
    }
    if (!isFailedEventStartRetry_) {
        isFailedEventStartRetry_ = true;
        ffrt::submit([this] { RetrySubscriptionTask(); });
    }
    SGLOGI("LoadAllPlugins finished");
}

void DetectPluginManager::LoadPlugin(const PluginCfg &pluginCfg)
{
    void *handle = dlopen(pluginCfg.pluginPath.c_str(), RTLD_LAZY);
    if (handle == nullptr) {
        SGLOGE("Plugin open failed, pluginName: %{private}s, reason: %{public}s",
            pluginCfg.pluginName.c_str(), dlerror());
        return;
    }
    std::shared_ptr<DetectPluginAttrs> detectPluginAttrs = std::make_shared<DetectPluginAttrs>();
    detectPluginAttrs->SetPluginName(pluginCfg.pluginName);
    detectPluginAttrs->SetHandle(handle);
    auto createDetectPlugin = (CreateDetectPlugin)dlsym(handle, "CreateDetectPlugin");
    if (createDetectPlugin == nullptr) {
        SGLOGE("createDetectPlugin func is nullptr");
        return;
    }
    IDetectPlugin *instance = createDetectPlugin();
    if (instance == nullptr) {
        SGLOGE("IDetectPlugin instance is nullptr");
        return;
    }
    detectPluginAttrs->SetInstance(instance);
    if (!instance->Init()) {
        SGLOGE("Plugin init failed, pluginName: %{private}s", pluginCfg.pluginName.c_str());
        return;
    }
    for (const int64_t& eventId : pluginCfg.depEventIds) {
        size_t count = 0;
        {
            std::lock_guard<ffrt::mutex> lock(mutex_);
            count = eventIdMap_.count(eventId);
        }
        if (count == 0) {
            SubscribeEvent(eventId);
        }
        std::lock_guard<ffrt::mutex> lock(mutex_);
        eventIdMap_[eventId].emplace_back(detectPluginAttrs);
    }
    if (pluginCfg.depEventIds.empty()) {
        const int64_t sepcialId = -1;
        std::lock_guard<ffrt::mutex> lock(mutex_);
        eventIdMap_[sepcialId].emplace_back(detectPluginAttrs);
    }
    SGLOGI("Load plugin success, pluginName: %{private}s", pluginCfg.pluginName.c_str());
}

void DetectPluginManager::SubscribeEvent(int64_t eventId)
{
    SecurityCollector::Event sgEvent {};
    sgEvent.eventId = eventId;
    auto subscriber = std::make_shared<DetectPluginManagerSubscriber>(sgEvent);
    int32_t code = SecurityGuard::DataCollectManager::GetInstance().Subscribe(subscriber);
    if (code != SecurityGuard::SUCCESS) {
        SGLOGE("Subscribe failed, code: %{public}d, eventId: 0x%{public}" PRIx64 "in retry list", code, eventId);
        failedEventIdset_.insert(eventId);
        return;
    }
    SGLOGI("DetectPluginManager subscribe success, eventId: 0x%{public}" PRIx64, eventId);
}

void DetectPluginManager::RetrySubscriptionTask()
{
    int32_t retryInterval = 10;
    while (!failedEventIdset_.empty()) {
        auto tmpSet = failedEventIdset_;
        for (const auto eventId : tmpSet) {
            SGLOGI("Retry subscription event: 0x%{public}" PRIx64, eventId);
            failedEventIdset_.erase(eventId);
            SubscribeEvent(eventId);
        }
        if (failedEventIdset_.empty()) {
            break;
        }
        ffrt::this_task::sleep_for(std::chrono::seconds(retryInterval));
        retryInterval = std::min(retryInterval + RETRY_INTERVAL_INCREMENT, MAX_RETRY_INTERVAL);
    }
}

bool DetectPluginManager::ParsePluginConfig(const std::string &fileName)
{
    std::ios::pos_type pluginCfgFileMaxSize = 1 * 1024 * 1024;  // byte
    std::string jsonStr;
    if (!FileUtil::ReadFileToStr(fileName, pluginCfgFileMaxSize, jsonStr)) {
        SGLOGE("Read plugin cfg file error.");
        return false;
    }
    cJSON *inJson = cJSON_Parse(jsonStr.c_str());
    if (inJson == nullptr) {
        SGLOGE("Parse json error.");
        return false;
    }
    cJSON *plugins = cJSON_GetObjectItem(inJson, "plugins");
    if (plugins == nullptr || !cJSON_IsArray(plugins)) {
        SGLOGE("Json Parse Error: plugins is null or not an array.");
        cJSON_Delete(inJson);
        inJson = nullptr;
        return false;
    }
    ParsePluginConfigObjArray(plugins);
    cJSON_Delete(inJson);
    inJson = nullptr;
    return true;
}

void DetectPluginManager::ParsePluginConfigObjArray(const cJSON *plugins)
{
    int size = cJSON_GetArraySize(plugins);
    for (int i = 0; i < size; i++) {
        cJSON *item = cJSON_GetArrayItem(plugins, i);
        PluginCfg pluginCfg;
        if (!JsonUtil::GetString(item, "pluginName", pluginCfg.pluginName) ||
            !JsonUtil::GetString(item, "version", pluginCfg.version) ||
            !ParsePluginDepEventIds(item, pluginCfg.depEventIds)) {
            SGLOGE("Json Parse Error: pluginName or version or depEventIds not correct.");
            continue;
        }
        if (!CheckPluginNameAndSize(pluginCfg)) {
            continue;
        }
        plugins_.emplace_back(pluginCfg);
    }
}

bool DetectPluginManager::CheckPluginNameAndSize(PluginCfg &newPlugin)
{
    if (plugins_.size() >= MAX_PLUGIN_SIZE) {
        SGLOGE("The number of managed plugins exceeds the specification");
        return false;
    }

    const std::string path = PLUGIN_PREFIX_PATH + newPlugin.pluginName;
    if (!PathToRealPath(path, newPlugin.pluginPath) || newPlugin.pluginPath.find(PLUGIN_PREFIX_PATH) != 0) {
        SGLOGE("Check plugin path failed, pluginName: %{private}s", newPlugin.pluginName.c_str());
        return false;
    }
    auto it = std::find_if(plugins_.begin(), plugins_.end(),
        [&](const PluginCfg &plugin) {return plugin.pluginName == newPlugin.pluginName;});
    if (it != plugins_.end()) {
        SGLOGE("Duplicate plugin names are not allowed.");
        return false;
    }
    return true;
}

bool DetectPluginManager::ParsePluginDepEventIds(const cJSON *plugin,
    std::unordered_set<int64_t> &depEventIds)
{
    cJSON *depEventIdsJson = cJSON_GetObjectItem(plugin, "depEventIds");
    if (depEventIdsJson == nullptr || !cJSON_IsArray(depEventIdsJson)) {
        SGLOGE("Json Parse Error: depEventIds not correct.");
        return false;
    }
    int size = cJSON_GetArraySize(depEventIdsJson);
    for (int i = 0; i < size; i++) {
        cJSON *eventIdJson = cJSON_GetArrayItem(depEventIdsJson, i);
        std::string eventId;
        if (!JsonUtil::GetStringNoKey(eventIdJson, eventId)) {
            SGLOGE("Json Parse Error: eventId not correct.");
            return false;
        }
        int64_t tmp = 0;
        if (!SecurityGuardUtils::StrToI64Hex(eventId, tmp)) {
            SGLOGE("Json Parse Error: eventId not int_64.");
            return false;
        }
        depEventIds.insert(tmp);
    }
    return true;
}

void DetectPluginManager::DispatchEvent(const SecurityCollector::Event &event)
{
    SGLOGD("Start distributing events, eventId: 0x%{public}" PRIx64, event.eventId);
    std::lock_guard<ffrt::mutex> lock(mutex_);
    auto it = eventIdMap_.find(event.eventId);
    if (it == eventIdMap_.end()) {
        SGLOGE("No Plugin is available to process th event, eventId: 0x%{public}" PRIx64,
             event.eventId);
        return;
    }
    for (auto& detectPlugin : it->second) {
        detectPlugin->GetInstance()->HandleEvent(event.eventId, event.content,
            AssembleMetadata(event));
        SGLOGD("Event distributed successfully, eventId: 0x%{public}" PRIx64 ", pluginName: %{private}s",
            event.eventId, detectPlugin->GetPluginName().c_str());
    }
}

std::string DetectPluginManager::AssembleMetadata(const SecurityCollector::Event &event)
{
    std::string metadata = "";
    cJSON* jsonObj = cJSON_CreateObject();
    if (jsonObj == nullptr) {
        SGLOGE("cJSON_CreateObject nullptr");
        return metadata;
    }
    do {
        if (!JsonUtil::AddString(jsonObj, "version", event.version)) {
            SGLOGE("AddString version failed");
            break;
        }
        if (!JsonUtil::AddString(jsonObj, "timestamp", event.timestamp)) {
            SGLOGE("AddString timestamp failed");
            break;
        }
        auto charPtr = cJSON_PrintUnformatted(jsonObj);
        if (charPtr == nullptr) {
            SGLOGE("cJSON_PrintUnformatted nullptr");
            break;
        }
        metadata = charPtr;
        cJSON_free(charPtr);
        charPtr= nullptr;
    } while (0);

    cJSON_Delete(jsonObj);
    jsonObj = nullptr;
    return metadata;
}
} // namespace OHOS::Security::SecurityGuard