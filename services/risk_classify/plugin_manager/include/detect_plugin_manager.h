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
#ifndef DETECT_PLUGIN_MANAGER_H
#define DETECT_PLUGIN_MANAGER_H

#include <dlfcn.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include "ffrt.h"
#include "cJSON.h"

#include "i_collector_subscriber.h"
#include "security_guard_log.h"
#include "security_guard_define.h"
#include "i_detect_plugin.h"

namespace OHOS::Security::SecurityGuard {
class DetectPluginManager {
public:
    static DetectPluginManager& getInstance();
    DetectPluginManager(const DetectPluginManager&) = delete;
    DetectPluginManager &operator=(const DetectPluginManager &) = delete;
    void LoadAllPlugins(const std::string &fileName);
    void DispatchEvent(const SecurityCollector::Event &event);

private:
    class DetectPluginManagerSubscriber : public SecurityCollector::ICollectorSubscriber {
    public:
        DetectPluginManagerSubscriber(SecurityCollector::Event event)
            : SecurityCollector::ICollectorSubscriber(event){};
        ~DetectPluginManagerSubscriber() override = default;
        int32_t OnNotify(const SecurityCollector::Event &event) override
        {
            DetectPluginManager::getInstance().DispatchEvent(event);
            return SecurityGuard::SUCCESS;
        };
    };

    class DetectPluginAttrs {
    public:
        DetectPluginAttrs() = default;
        ~DetectPluginAttrs()
        {
            SGLOGI("~DetectPluginAttrs");
            if (instance_ != nullptr) {
                instance_->Destroy();
                delete instance_;
                instance_ = nullptr;
            }
            if (handle_ != nullptr) {
                handle_ = nullptr;
            }
        };

        void SetHandle(void *handle) { handle_ = handle; };
        void SetInstance(IDetectPlugin *instance) { instance_ = instance; };
        void SetPluginName(std::string pluginName) { pluginName_ = pluginName; };
        void *GetHandle() { return handle_; };
        IDetectPlugin *GetInstance() { return instance_; };
        std::string GetPluginName() { return pluginName_; };

    private:
        void *handle_ = nullptr;
        IDetectPlugin *instance_ = nullptr;
        std::string pluginName_;
    };

    struct PluginCfg {
        std::string pluginName;
        std::string pluginPath;
        std::unordered_set<int64_t> depEventIds;
        std::string version;
    };

    std::vector<PluginCfg> plugins_;
    std::unordered_map<int64_t, std::vector<std::shared_ptr<DetectPluginAttrs>>> eventIdMap_;
    std::unordered_set<int64_t> failedEventIdset_;
    bool isFailedEventStartRetry_ = false;
    DetectPluginManager() = default;
    ~DetectPluginManager() = default;
    void LoadPlugin(const PluginCfg &pluginCfg);
    void SubscribeEvent(int64_t eventId);
    void RetrySubscriptionTask();
    bool ParsePluginConfig(const std::string &fileName);
    void ParsePluginConfigObjArray(const cJSON *plugins);
    bool CheckPluginNameAndSize(PluginCfg &newPlugin);
    bool ParsePluginDepEventIds(const cJSON *plugin, std::unordered_set<int64_t> &depEventIds);
    std::string AssembleMetadata(const SecurityCollector::Event &event);
    ffrt::mutex mutex_;
};
}  // namespace OHOS::Security::SecurityGuard
#endif