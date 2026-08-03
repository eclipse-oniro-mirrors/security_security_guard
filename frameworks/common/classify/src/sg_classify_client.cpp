/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "sg_classify_client.h"

#ifndef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
#include <future>
#include "iremote_broker.h"
#include "iservice_registry.h"
#include "securec.h"
#include "risk_analysis_manager_callback_service.h"
#include "risk_analysis_manager_proxy.h"
#include "risk_analysis_manager.h"
#endif

#include "security_guard_define.h"
#include "security_guard_log.h"

#ifndef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
namespace {
    constexpr int32_t TIMEOUT_REPLY = 15000;
}

using namespace OHOS;
using namespace OHOS::Security::SecurityGuard;

static std::mutex g_mutex;

static int32_t RequestSecurityModelResult(const std::string &devId, uint32_t modelId,
    const std::string &param, ResultCallback callback)
{
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return NULL_OBJECT;
    }

    auto object = registry->GetSystemAbility(RISK_ANALYSIS_MANAGER_SA_ID);
    auto proxy = iface_cast<RiskAnalysisManager>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }

    sptr<RiskAnalysisManagerCallbackService> stub = new (std::nothrow) RiskAnalysisManagerCallbackService(callback);
    if (stub == nullptr) {
        SGLOGE("stub is null");
        return NULL_OBJECT;
    }
    int32_t ret = proxy->RequestSecurityModelResult(devId, modelId, param, stub);
    SGLOGI("RequestSecurityModelResult result, ret=%{public}d", ret);
    return ret;
}
#endif
namespace OHOS::Security::SecurityGuard {
int32_t RequestSecurityModelResultSync(const std::string &devId, uint32_t modelId,
    const std::string &param, SecurityModelResult &result)
{
#ifndef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
    if (devId.length() >= DEVICE_ID_MAX_LEN) {
        return BAD_PARAM;
    }
    std::unique_lock<std::mutex> lock(g_mutex);
    auto promise = std::make_shared<std::promise<SecurityModelResult>>();
    auto future = promise->get_future();
    auto func = [promise, param] (const std::string &devId, uint32_t modelId,
        const std::string &result) mutable -> int32_t {
        SecurityModelResult modelResult = {
            .devId = devId,
            .modelId = modelId,
            .param = param,
            .result = result
        };
        promise->set_value(modelResult);
        return SUCCESS;
    };

    int32_t code = RequestSecurityModelResult(devId, modelId, param, func);
    if (code != SUCCESS) {
        SGLOGE("RequestSecurityModelResult error, code=%{public}d", code);
        return code;
    }
    std::chrono::milliseconds span(TIMEOUT_REPLY);
    if (future.wait_for(span) == std::future_status::timeout) {
        SGLOGE("wait timeout");
        return TIME_OUT;
    }
    result = future.get();
    return SUCCESS;
#else
    return 0;
#endif
}

int32_t RequestSecurityModelResultAsync(const std::string &devId, uint32_t modelId,
    const std::string &param, SecurityGuardRiskCallback callback)
{
#ifndef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
    if (devId.length() >= DEVICE_ID_MAX_LEN || callback == nullptr) {
        return BAD_PARAM;
    }
    std::unique_lock<std::mutex> lock(g_mutex);
    auto func = [callback, param] (const std::string &devId,
        uint32_t modelId, const std::string &result) -> int32_t {
        callback(SecurityModelResult{devId, modelId, param, result});
        return SUCCESS;
    };

    return RequestSecurityModelResult(devId, modelId, param, func);
#else
    return 0;
#endif
}

int32_t StartSecurityModel(uint32_t modelId, const std::string &param)
{
    SGLOGI("enter StartSecurityModel");
#ifndef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return NULL_OBJECT;
    }

    auto object = registry->GetSystemAbility(RISK_ANALYSIS_MANAGER_SA_ID);
    auto proxy = iface_cast<RiskAnalysisManager>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }

    int32_t ret = proxy->StartSecurityModel(modelId, param);
    SGLOGI("StartSecurityModel result, ret=%{public}d", ret);
    return ret;
#else
    return 0;
#endif
}
}

#ifdef __cplusplus
extern "C" {
#endif
#ifndef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
static int32_t FillingRequestResult(const OHOS::Security::SecurityGuard::SecurityModelResult &cppResult,
    ::SecurityModelResult *result)
{
    if (cppResult.devId.length() >= DEVICE_ID_MAX_LEN || cppResult.result.length() >= RESULT_MAX_LEN) {
        return BAD_PARAM;
    }

    result->modelId = cppResult.modelId;
    errno_t rc = memcpy_s(result->devId.identity, DEVICE_ID_MAX_LEN, cppResult.devId.c_str(), cppResult.devId.length());
    if (rc != EOK) {
        return NULL_OBJECT;
    }
    result->devId.length = cppResult.devId.length();

    rc = memcpy_s(result->result, RESULT_MAX_LEN, cppResult.result.c_str(), cppResult.result.length());
    if (rc != EOK) {
        return NULL_OBJECT;
    }
    result->resultLen = cppResult.result.length();

    SGLOGD("modelId=%{public}u, result=%{private}s", cppResult.modelId, cppResult.result.c_str());
    return SUCCESS;
}

static std::string CovertDevId(const DeviceIdentify *devId)
{
    std::vector<char> id(DEVICE_ID_MAX_LEN, '\0');
    std::copy(&devId->identity[0], &devId->identity[DEVICE_ID_MAX_LEN - 1], id.begin());
    return std::string{id.data()};
}
#endif
int32_t RequestSecurityModelResultSync(const DeviceIdentify *devId, uint32_t modelId, ::SecurityModelResult *result)
{
#ifndef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
    if (devId == nullptr || result == nullptr || devId->length >= DEVICE_ID_MAX_LEN) {
        return BAD_PARAM;
    }
    OHOS::Security::SecurityGuard::SecurityModelResult tmp;
    int32_t ret = OHOS::Security::SecurityGuard::RequestSecurityModelResultSync(CovertDevId(devId), modelId, "", tmp);
    FillingRequestResult(tmp, result);
    return ret;
#else
    return 0;
#endif
}

int32_t RequestSecurityModelResultAsync(const DeviceIdentify *devId, uint32_t modelId,
    ::SecurityGuardRiskCallback callback)
{
#ifndef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
    if (devId == nullptr || devId->length >= DEVICE_ID_MAX_LEN || callback == nullptr) {
        return BAD_PARAM;
    }
    auto cppCallBack = [callback](const OHOS::Security::SecurityGuard::SecurityModelResult &tmp) {
        ::SecurityModelResult result{};
        FillingRequestResult(tmp, &result);
        callback(&result);
    };
    return OHOS::Security::SecurityGuard::RequestSecurityModelResultAsync(CovertDevId(devId), modelId, "", cppCallBack);
#else
    return 0;
#endif
}

#ifdef __cplusplus
}
#endif
