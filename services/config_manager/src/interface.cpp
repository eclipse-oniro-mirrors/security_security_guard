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

#include "config_manager.h"
#include "config_subscriber.h"
#include "event_group_config.h"
#include "security_guard_log.h"

extern "C" bool InitAllConfig()
{
    bool success = true;
    if (!OHOS::Security::SecurityGuard::ConfigManager::InitConfig<OHOS::Security::SecurityGuard::EventConfig>()) {
        SGLOGE("init event config error");
        success = false;
    }

    if (!OHOS::Security::SecurityGuard::ConfigManager::InitConfig<OHOS::Security::SecurityGuard::ModelConfig>()) {
        SGLOGE("init model config error");
        success = false;
    }

    if (!OHOS::Security::SecurityGuard::ConfigManager::InitConfig<OHOS::Security::SecurityGuard::EventGroupConfig>()) {
        SGLOGE("init event group config error");
        success = false;
    }
    return success;
}

extern "C" bool UpdateConfig(const std::string &file)
{
    return OHOS::Security::SecurityGuard::ConfigSubscriber::UpdateConfig(file);
}