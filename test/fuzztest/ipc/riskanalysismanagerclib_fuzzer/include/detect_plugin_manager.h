/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <string>

#include "i_collector_subscriber.h"

namespace OHOS::Security::SecurityGuard {
// Mock version for RiskAnalysisManagerClibFuzzTest: shadow the real header via
// include_dirs order, all methods are no-op to avoid linking detect_plugin_manager.cpp.
class DetectPluginManager {
public:
    static DetectPluginManager& getInstance()
    {
        static DetectPluginManager instance;
        return instance;
    }
    DetectPluginManager(const DetectPluginManager&) = delete;
    DetectPluginManager &operator=(const DetectPluginManager &) = delete;
    void LoadAllPlugins(const std::string &fileName) {}
    void DispatchEvent(const SecurityCollector::Event &event) {}
    void StopRetryTask() {}

private:
    DetectPluginManager() = default;
    ~DetectPluginManager() = default;
};
}  // namespace OHOS::Security::SecurityGuard
#endif
