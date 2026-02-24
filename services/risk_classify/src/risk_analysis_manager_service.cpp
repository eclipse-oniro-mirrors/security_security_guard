/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "risk_analysis_manager_service.h"

#include <thread>
#include <cinttypes>

#include "accesstoken_kit.h"
#include "tokenid_kit.h"
#include "ipc_skeleton.h"
#include "cJSON.h"
#include "ffrt.h"

#include "bigdata.h"
#include "database_manager.h"
#include "errors.h"
#include "model_manager.h"
#include "event_group_config.h"
#include "risk_analysis_define.h"
#include "risk_analysis_manager_callback_proxy.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "system_ability_definition.h"
#include "ffrt.h"
#include "config_manager.h"
#include "store_define.h"
#include "detect_plugin_manager.h"

namespace OHOS::Security::SecurityGuard {
REGISTER_SYSTEM_ABILITY_BY_ID(RiskAnalysisManagerService, RISK_ANALYSIS_MANAGER_SA_ID, true);

namespace {
    constexpr int32_t TIMEOUT_REPLY = 15000;
    constexpr int32_t DELAY_TIME = 5000;
    constexpr const char* REQUEST_PERMISSION = "ohos.permission.securityguard.REQUEST_SECURITY_MODEL_RESULT";
    constexpr const char* QUERY_SECURITY_MODEL_RESULT_PERMISSION = "ohos.permission.QUERY_SECURITY_MODEL_RESULT";
    const std::vector<uint32_t> MODELIDS = {
        3001000000, 3001000001, 3001000002, 3001000005, 3001000006, 3001000007, 3001000009, 3001000011
    };
    const std::unordered_map<std::string, std::vector<std::string>> g_apiPermissionsMap {
        {"RequestSecurityModelResult", {REQUEST_PERMISSION, QUERY_SECURITY_MODEL_RESULT_PERMISSION}},
        {"StartSecurityModel", {QUERY_SECURITY_MODEL_RESULT_PERMISSION}},
    };
    typedef void (*InitAllConfigFunc)();
}

RiskAnalysisManagerService::RiskAnalysisManagerService(int32_t saId, bool runOnCreate)
    : SystemAbility(saId, runOnCreate)
{
    SGLOGW("%{public}s", __func__);
}

void RiskAnalysisManagerService::OnStart()
{
    SGLOGI("RiskAnalysisManagerService %{public}s", __func__);
    void *handle = dlopen("libsg_config_manager.z.so", RTLD_LAZY);
    if (handle == nullptr) {
        SGLOGE("dlopen error: %{public}s", dlerror());
    } else {
        auto func = (InitAllConfigFunc)dlsym(handle, "InitAllConfig");
        if (func != nullptr) {
            func();
            SGLOGI("Call Init All Config");
        } else {
            SGLOGE("dlsym error: %{public}s", dlerror());
        }
        dlclose(handle);
    }
    ModelManager::GetInstance().Init();
    if (!Publish(this)) {
        SGLOGE("Publish error");
    }
    ffrt::submit([this] {
        ffrt::this_task::sleep_for(std::chrono::milliseconds(DELAY_TIME));
        const std::string fileName = "/system/etc/detect_plugin.json";
        DetectPluginManager::getInstance().LoadAllPlugins(fileName);
    });
}

void RiskAnalysisManagerService::OnStop()
{
}

int32_t RiskAnalysisManagerService::IsCallerHasApiPermission(const std::string &api)
{
    if (g_apiPermissionsMap.count(api) == 0) {
        SGLOGE("api not in map");
        return FAILED;
    }
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    if (std::any_of(g_apiPermissionsMap.at(api).cbegin(), g_apiPermissionsMap.at(api).cend(),
        [callerToken](const std::string &per) {
        int code = AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, per);
        return code == AccessToken::PermissionState::PERMISSION_GRANTED;
    })) {
        AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenType(callerToken);
        if (tokenType != AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
            uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
            if (!AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)) {
                SGLOGE("not system app no permission");
                return NO_SYSTEMCALL;
            }
        }
        return SUCCESS;
    }
    SGLOGE("caller no permission");
    return NO_PERMISSION;
}

ErrCode RiskAnalysisManagerService::RequestSecurityModelResult(const std::string &devId, uint32_t modelId,
    const std::string &param, const sptr<IRemoteObject> &cb)
{
    SGLOGI("enter RiskAnalysisManagerService RequestSecurityModelResult");
    int32_t ret = IsCallerHasApiPermission("RequestSecurityModelResult");
    if (ret != SUCCESS) {
        return ret;
    }
    ClassifyEvent event;
    event.pid = IPCSkeleton::GetCallingPid();
    event.time = SecurityGuardUtils::GetDate();
    auto promise = std::make_shared<std::promise<std::string>>();
    auto future = promise->get_future();
    PushRiskAnalysisTask(modelId, param, promise);
    std::chrono::milliseconds span(TIMEOUT_REPLY);
    std::string result{};
    if (future.wait_for(span) == std::future_status::timeout) {
        SGLOGE("wait for result timeout");
        ret = TIME_OUT;
    } else {
        result = future.get();
        ret =  SUCCESS;
    }
    SGLOGI("ReportClassifyEvent");
    event.status = result;
    BigData::ReportClassifyEvent(event);
    auto proxy = iface_cast<IRiskAnalysisManagerCallback>(cb);
    if (proxy == nullptr) {
        return NULL_OBJECT;
    }
    proxy->ResponseSecurityModelResult(devId, modelId, result);
    SGLOGI("get analysis result=%{private}s", result.c_str());
    return ret;
}

void RiskAnalysisManagerService::PushRiskAnalysisTask(uint32_t modelId, std::string param,
    std::shared_ptr<std::promise<std::string>> promise)
{
    auto task = [modelId, param, promise] {
        SGLOGD("modelId=%{public}u", modelId);
        if (std::count(MODELIDS.begin(), MODELIDS.end(), modelId) == 0) {
            SGLOGE("model not support, no need to analyse, modelId=%{public}u", modelId);
            promise->set_value(UNKNOWN_STATUS);
            return;
        }
        std::string result = ModelManager::GetInstance().GetResult(modelId, param);
        SGLOGI("result is %{private}s", result.c_str());
        promise->set_value(result);
    };
    ffrt::submit(task);
}

ErrCode RiskAnalysisManagerService::SetModelState(uint32_t modelId, bool enable)
{
    return SUCCESS;
}

ErrCode RiskAnalysisManagerService::StartSecurityModel(uint32_t modelId, const std::string &param)
{
    SGLOGI("enter RiskAnalysisManagerService StartSecurityModel");
    int32_t ret = IsCallerHasApiPermission("StartSecurityModel");
    if (ret != SUCCESS) {
        return ret;
    }
    return ModelManager::GetInstance().StartSecurityModel(modelId, param);
}

void RiskAnalysisManagerService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    SGLOGI("OnAddSystemAbility, systemAbilityId=%{public}d", systemAbilityId);
}

void RiskAnalysisManagerService::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    SGLOGW("OnRemoveSystemAbility, systemAbilityId=%{public}d", systemAbilityId);
}
}
