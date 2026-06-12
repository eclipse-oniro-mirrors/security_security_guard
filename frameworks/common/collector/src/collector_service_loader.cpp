/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "collector_service_loader.h"

#include "if_system_ability_manager.h"
#include "isystem_ability_load_callback.h"
#include "iservice_registry.h"

#include "i_security_collector_manager.h"
#include "security_collector_log.h"


namespace OHOS::Security::SecurityCollector {
sptr<IRemoteObject> CollectorServiceLoader::LoadCollectorService()
{
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        LOGE("GetSystemAbilityManager error.");
        return nullptr;
    }
    auto object = registry->CheckSystemAbility(SECURITY_COLLECTOR_MANAGER_SA_ID);
    if (object != nullptr) {
        return object;
    }

    sptr<LoadCallback> callback = new (std::nothrow) LoadCallback();
    if (callback == nullptr) {
        LOGE("LoadCallback new error.");
        return nullptr;
    }
    int32_t result = registry->LoadSystemAbility(SECURITY_COLLECTOR_MANAGER_SA_ID, callback);
    if (result != ERR_OK) {
        LOGE("LoadSystemAbility error.");
        return nullptr;
    }
    return callback->Promise();
}

void CollectorServiceLoader::LoadCallback::OnLoadSystemAbilitySuccess(int32_t sid, const sptr<IRemoteObject> &object)
{
    LOGD("OnLoadSystemAbilitySuccess = %{public}d.", sid);
    promise_.set_value(object);
}

void CollectorServiceLoader::LoadCallback::OnLoadSystemAbilityFail(int32_t sid)
{
    LOGI("OnLoadSystemAbilityFail = %{public}d.", sid);
}

sptr<IRemoteObject> CollectorServiceLoader::LoadCallback::Promise()
{
    constexpr int32_t TimeoutInterval = 1;
    auto future = promise_.get_future();
    auto span = std::chrono::seconds(TimeoutInterval);
    if (future.wait_for(span) == std::future_status::timeout) {
        LOGE("LoadCallback Get Promise Timeout");
        return nullptr;
    } else {
        return future.get();
    }
}
} // namespace OHOS::Security::SecurityAudit