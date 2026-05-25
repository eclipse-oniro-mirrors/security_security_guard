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
#include "security_guard_napi.h"
#include <future>
#include <unistd.h>
#include <syscall.h>
#include <unordered_map>
#include <map>
#include <algorithm>

#include "napi_request_data_manager.h"
#include "napi_security_event_querier.h"
#include "security_event.h"
#include "security_config_update_info.h"
#include "security_event_ruler.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_sdk_adaptor.h"
#include "i_collector_subscriber.h"
#include "uv.h"

#include "securec.h"

using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityCollector;
constexpr std::size_t ARGS_SIZE_ONE = 1;
constexpr std::size_t ARGS_SIZE_THREE = 3;
constexpr std::size_t ARGS_SIZE_TWO = 2;
constexpr int PARAMZERO = 0;
constexpr int PARAMONE = 1;
constexpr char NAPI_EVENT_EVENT_ID_ATTR[] = "eventId";
constexpr char NAPI_EVENT_VERSION_ATTR[] = "version";
constexpr char NAPI_EVENT_CONTENT_ATTR[] = "content";

constexpr int VERSION_MAX_LEN = 50;
constexpr int EXTRA_MAX_LEN = 2000;
constexpr int FILE_NAME_MAX_LEN = 64;
constexpr int ALL_PROPERTY_MAX_LEN = 2048;

constexpr int NAPI_START_COLLECTOR_ARGS_CNT = 2;
constexpr int NAPI_STOP_COLLECTOR_ARGS_CNT = 1;
constexpr int NAPI_REPORT_EVENT_INFO_ARGS_CNT = 1;
constexpr int NAPI_UPDATE_POLICY_FILE_ARGS_CNT = 1;
#ifndef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
constexpr int MODEL_NAME_MAX_LEN = 64;
constexpr int PARAM_MAX_LEN = 900;
constexpr int32_t TIMEOUT_REPLY = 15000;
constexpr char NAPI_SECURITY_MODEL_RESULT_DEVICE_ID_ATTR[] = "deviceId";
constexpr char NAPI_SECURITY_MODEL_RESULT_MODEL_ID_ATTR[] = "modelId";
constexpr char NAPI_SECURITY_MODEL_RESULT_RESULT_ATTR[] = "result";
constexpr int NAPI_GET_MODEL_RESULT_ARGS_CNT = 1;
#endif
constexpr int NAPI_QUERY_SECURITY_EVENT_ARGS_CNT = 2;

constexpr int TIME_MAX_LEN = 15;

using NAPI_QUERIER_PAIR = std::pair<pid_t, std::shared_ptr<NapiSecurityEventQuerier>>;
static std::unordered_map<napi_ref, NAPI_QUERIER_PAIR> queriers;
static std::mutex g_subscribeMutex;
static std::mutex g_queryMutex;
std::map<napi_env, std::vector<SubscribeCBInfo *>> g_subscribers;

static const std::unordered_map<int32_t, std::pair<int32_t, std::string>> g_errorStringMap = {
    { SUCCESS, { JS_ERR_SUCCESS, "The operation was successful" }},
    { NO_PERMISSION, { JS_ERR_NO_PERMISSION, "check permission fail"} },
    { BAD_PARAM, { JS_ERR_BAD_PARAM, "Parameter error, please make sure using the correct value"} },
    { NO_SYSTEMCALL, { JS_ERR_NO_SYSTEMCALL, "non-system application uses the system API"} },
    { API_SUPPORT_ERROR, { JS_ERR_API_SUPPORT_ERROR, "API is not supported"} },
};

static std::string ConvertToJsErrMsg(int32_t code)
{
    auto iter = g_errorStringMap.find(code);
    if (iter != g_errorStringMap.end()) {
        return iter->second.second;
    } else {
        return "Unknown error, please reboot your device and try again";
    }
}

static int32_t ConvertToJsErrCode(int32_t code)
{
    auto iter = g_errorStringMap.find(code);
    if (iter != g_errorStringMap.end()) {
        return iter->second.first;
    } else {
        return JS_ERR_SYS_ERR;
    }
}

static napi_value NapiCreateObject(const napi_env env)
{
    napi_value result = nullptr;
    napi_status status = napi_create_object(env, &result);
    if (status != napi_ok || result == nullptr) {
        SGLOGE("failed to create napi value of object type.");
    }
    return result;
}

static napi_value NapiCreateString(const napi_env env, const std::string &value)
{
    napi_value result = nullptr;
    napi_status status = napi_create_string_utf8(env, value.c_str(), NAPI_AUTO_LENGTH, &result);
    SGLOGD("create napi value of string type, value is %{public}s.", value.c_str());
    if (status != napi_ok || result == nullptr) {
        SGLOGE("failed to create napi value of string type.");
    }
    return result;
}

static napi_value NapiCreateInt64(const napi_env env, int64_t value)
{
    napi_value result = nullptr;
    napi_status status = napi_create_int64(env, value, &result);
    SGLOGI("create napi value of int64 type, value is %{public}" PRId64, value);
    if (status != napi_ok || result == nullptr) {
        SGLOGE("failed to create napi value of int64 type.");
    }
    return result;
}

static napi_value NapiCreateInt32(const napi_env env, int32_t value)
{
    napi_value result = nullptr;
    napi_status status = napi_create_int32(env, value, &result);
    SGLOGD("create napi value of int32 type, value is %{public}d.", value);
    if (status != napi_ok || result == nullptr) {
        SGLOGE("failed to create napi value of int32 type.");
    }
    return result;
}
#ifndef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
static napi_value NapiCreateUint32(const napi_env env, uint32_t value)
{
    napi_value result = nullptr;
    napi_status status = napi_create_uint32(env, value, &result);
    SGLOGI("create napi value of uint32 type, value is %{public}u.", value);
    if (status != napi_ok || result == nullptr) {
        SGLOGE("failed to create napi value of uint32 type.");
    }
    return result;
}
#endif
static napi_value GenerateBusinessError(napi_env env, int32_t code)
{
    napi_value result;
    SGLOGD("GenerateBusinessError code:%{public}d", code);
    if (code == SUCCESS) {
        napi_get_undefined(env, &result);
    } else {
        int32_t jsErrCode = ConvertToJsErrCode(code);
        napi_value errCode = NapiCreateInt32(env, jsErrCode);

        std::string errMsgStr = ConvertToJsErrMsg(code);
        napi_value errMsg = NapiCreateString(env, errMsgStr);

        napi_create_error(env, nullptr, errMsg, &result);
        napi_set_named_property(env, result, "code", errCode);
        napi_set_named_property(env, result, "message", errMsg);
    }
    return result;
}

static napi_value GenerateBusinessError(napi_env env, int32_t code, const std::string &msg)
{
    napi_value result;
    SGLOGD("GenerateBusinessError code:%{public}d", code);
    if (code == SUCCESS) {
        napi_get_undefined(env, &result);
    } else {
        int32_t jsErrCode = ConvertToJsErrCode(code);
        napi_value errCode = NapiCreateInt32(env, jsErrCode);
        napi_value errMsg = NapiCreateString(env, msg);

        napi_create_error(env, nullptr, errMsg, &result);
        napi_set_named_property(env, result, "code", errCode);
        napi_set_named_property(env, result, "message", errMsg);
    }
    return result;
}

static napi_value ParseInt64(napi_env env, napi_value object, const std::string &key, int64_t &value)
{
    napi_value result;
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, object, key.c_str(), &hasProperty));
    if (!hasProperty) {
        std::string msg = "no such param" + key;
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, msg));
        return nullptr;
    }
    NAPI_CALL(env, napi_get_named_property(env, object, key.c_str(), &result));
    if (result == nullptr) {
        SGLOGE("get %{public}s failed", key.c_str());
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "get key failed."));
        return nullptr;
    }

    napi_valuetype type;
    NAPI_CALL(env, napi_typeof(env, result, &type));
    if (type != napi_number) {
        SGLOGE("type of param %{public}s is not number", key.c_str());
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "type of param is not number."));
        return nullptr;
    }

    NAPI_CALL(env, napi_get_value_int64(env, result, &value));
    return NapiCreateInt64(env, ConvertToJsErrCode(SUCCESS));
}

static napi_value ParseInt32(napi_env env, napi_value object, const std::string &key, int32_t &value)
{
    napi_value result;
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, object, key.c_str(), &hasProperty));
    if (!hasProperty) {
        std::string msg = "no such param" + key;
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, msg));
        return nullptr;
    }
    NAPI_CALL(env, napi_get_named_property(env, object, key.c_str(), &result));
    if (result == nullptr) {
        SGLOGE("get %{public}s failed", key.c_str());
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "get key failed."));
        return nullptr;
    }

    napi_valuetype type;
    NAPI_CALL(env, napi_typeof(env, result, &type));
    if (type != napi_number) {
        SGLOGE("type of param %{public}s is not number", key.c_str());
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "type of param is not number."));
        return nullptr;
    }

    NAPI_CALL(env, napi_get_value_int32(env, result, &value));
    return NapiCreateInt32(env, ConvertToJsErrCode(SUCCESS));
}

static napi_value GetString(napi_env env, napi_value object, const std::string &key, char *value, size_t &maxLen)
{
    napi_valuetype type;
    NAPI_CALL(env, napi_typeof(env, object, &type));
    if (type != napi_string) {
        std::string msg = "param " + key + " is not string";
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, msg));
        return nullptr;
    }

    size_t size = 0;
    NAPI_CALL(env, napi_get_value_string_utf8(env, object, nullptr, 0, &size));
    if (size >= maxLen) {
        std::string msg = "param " + key + " is too long";
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, msg));
        return nullptr;
    }

    maxLen = size + 1;
    NAPI_CALL(env, napi_get_value_string_utf8(env, object, value, maxLen, &maxLen));
    return NapiCreateInt32(env, SUCCESS);
}

static napi_value ParseString(napi_env env, napi_value object, const std::string &key, char *value, size_t &maxLen)
{
    napi_value result;
    NAPI_CALL(env, napi_get_named_property(env, object, key.c_str(), &result));
    if (result == nullptr) {
        std::string msg = "param " + key + " is not found";
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, msg));
        return nullptr;
    }

    return GetString(env, result, key, value, maxLen);
}

static napi_value ParseEventInfo(napi_env env, napi_value object, ReportSecurityEventInfoContext *context)
{
    napi_valuetype type = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, object, &type));
    if (type != napi_object) {
        GenerateBusinessError(env, BAD_PARAM, "type of param eventInfo is not object");
        return nullptr;
    }

    if (ParseInt64(env, object, "eventId", context->eventId) == nullptr) {
        return nullptr;
    }

    char version[VERSION_MAX_LEN] = {0};
    size_t len = VERSION_MAX_LEN;
    if (ParseString(env, object, "version", version, len) == nullptr) {
        return nullptr;
    }
    context->version = version;

    char content[CONTENT_MAX_LEN] = {0};
    len = CONTENT_MAX_LEN;
    if (ParseString(env, object, "content", content, len) == nullptr) {
        return nullptr;
    }
    context->content = content;
    return NapiCreateInt32(env, SUCCESS);
}

static napi_value NapiReportSecurityInfo(napi_env env, napi_callback_info info)
{
    size_t argc = NAPI_REPORT_EVENT_INFO_ARGS_CNT;
    napi_value argv[NAPI_REPORT_EVENT_INFO_ARGS_CNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != NAPI_REPORT_EVENT_INFO_ARGS_CNT) {
        SGLOGE("report eventInfo arguments count is not expected");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM));
        return nullptr;
    }

    ReportSecurityEventInfoContext context = {};
    napi_value ret = ParseEventInfo(env, argv[0], &context);
    if (ret == nullptr) {
        SGLOGE("report eventInfo parse error");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM));
        return nullptr;
    }

    auto eventInfo = std::make_shared<EventInfo>(context.eventId, context.version, context.content);
    int32_t code = SecurityGuardSdkAdaptor::InnerReportSecurityInfo(eventInfo);
    if (code != SUCCESS) {
        SGLOGE("report eventInfo error, code=%{public}d", code);
        napi_throw(env, GenerateBusinessError(env, code));
        return nullptr;
    }
    return NapiCreateInt32(env, SUCCESS);
}

static bool IsNum(const std::string &s)
{
    return std::all_of(s.begin(), s.end(), isdigit);
}

static napi_value GetConditionsTime(napi_env env, napi_value object, const std::string &key, std::string &value)
{
    char time[TIME_MAX_LEN] = {0};
    size_t len = TIME_MAX_LEN;
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, object, key.c_str(), &hasProperty));
    if (!hasProperty) {
        SGLOGE("no %{public}s param", key.c_str());
        return NapiCreateInt32(env, SUCCESS);
    }
    napi_value result;
    NAPI_CALL(env, napi_get_named_property(env, object, key.c_str(), &result));
    if (result == nullptr) {
        SGLOGE("get %{public}s failed", key.c_str());
        return nullptr;
    }

    result = GetString(env, result, key, time, len);
    if (result == nullptr) {
        SGLOGE("get %{public}s failed", key.c_str());
        return nullptr;
    }
    value = time;
    if (!IsNum(value) || value.length() != (TIME_MAX_LEN - 1)) {
        SGLOGE("time invalid %{public}s", key.c_str());
        return nullptr;
    }
    return NapiCreateInt32(env, SUCCESS);
}
#ifndef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
static void RequestSecurityModelResultExecute(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    auto *context = static_cast<RequestSecurityModelResultContext *>(data);
    auto promise = std::make_shared<std::promise<SecurityModel>>();
    auto future = promise->get_future();
    auto func = [promise] (const OHOS::Security::SecurityGuard::SecurityModelResult &result) mutable -> int32_t {
        SecurityModel model = {
            .devId = result.devId,
            .modelId = result.modelId,
            .result = result.result
        };
        promise->set_value(model);
        return SUCCESS;
    };
    context->ret =
        SecurityGuardSdkAdaptor::InnerRequestSecurityModelResult(context->deviceId, context->modelId,
            context->param, func);
    if (context->ret != SUCCESS) {
        SGLOGE("RequestSecurityModelResultSync error, ret=%{public}d", context->ret);
        return;
    }
    std::chrono::milliseconds span(TIMEOUT_REPLY);
    if (future.wait_for(span) == std::future_status::timeout) {
        SGLOGE("wait timeout");
        context->ret = TIME_OUT;
        return;
    }
    context->result = future.get();
}

static napi_value GenerateSecurityModelResult(napi_env env, RequestSecurityModelResultContext *context)
{
    napi_value ret = NapiCreateObject(env);
    if (ret == nullptr) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "napi create object error ."));
    }
    napi_value deviceId = NapiCreateString(env, context->result.devId.c_str());
    napi_value modelId = NapiCreateUint32(env, context->result.modelId);
    napi_value result = NapiCreateString(env, context->result.result.c_str());

    napi_set_named_property(env, ret, NAPI_SECURITY_MODEL_RESULT_DEVICE_ID_ATTR, deviceId);
    napi_set_named_property(env, ret, NAPI_SECURITY_MODEL_RESULT_MODEL_ID_ATTR, modelId);
    napi_set_named_property(env, ret, NAPI_SECURITY_MODEL_RESULT_RESULT_ATTR, result);
    return ret;
}

static napi_value GenerateReturnValue(napi_env env, RequestSecurityModelResultContext *context)
{
    napi_value result;
    if (context->ret == SUCCESS) {
        result = GenerateSecurityModelResult(env, context);
    } else {
        napi_get_undefined(env, &result);
    }
    return result;
}

static void RequestSecurityModelResultComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        return;
    }
    auto *context = static_cast<RequestSecurityModelResultContext *>(data);
    napi_value result[2] = {0};
    result[0] = GenerateBusinessError(env, context->ret);
    result[1] = GenerateReturnValue(env, context);
    if (context->ref != nullptr) {
        napi_value callbackfunc = nullptr;
        napi_get_reference_value(env, context->ref, &callbackfunc);
        napi_value returnVal;
        napi_call_function(env, nullptr, callbackfunc, sizeof(result) / sizeof(result[0]), result, &returnVal);
        napi_delete_reference(env, context->ref);
        context->ref = nullptr;
    } else {
        if (context->ret == SUCCESS) {
            napi_resolve_deferred(env, context->deferred, result[1]);
        } else {
            napi_reject_deferred(env, context->deferred, result[0]);
        }
    }
    napi_delete_async_work(env, context->asyncWork);
    delete context;
}

static napi_value ParseModelId(napi_env env, const std::string &modelNameStr, uint32_t &modelId)
{
    if (modelNameStr == "SecurityGuard_JailbreakCheck") {
        modelId = ModelIdType::ROOT_SCAN_MODEL_ID;
    } else if (modelNameStr == "SecurityGuard_IntegrityCheck") {
        modelId = ModelIdType::DEVICE_COMPLETENESS_MODEL_ID;
    } else if (modelNameStr == "SecurityGuard_SimulatorCheck") {
        modelId = ModelIdType::PHYSICAL_MACHINE_DETECTION_MODEL_ID;
    } else if (modelNameStr == "SecurityGuard_RiskFactorCheck") {
        modelId = ModelIdType::SECURITY_RISK_FACTOR_MODEL_ID;
    } else if (modelNameStr == "SecurityGuard_WifiCheck") {
        modelId = ModelIdType::WLAN_RISK_DETECTION_MODEL_ID;
    } else {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM,
            "Parameter error, please make sure using the correct model name"));
        return nullptr;
    }
    return NapiCreateInt32(env, SUCCESS);
}
#endif
static std::string ParseOptionalString(napi_env env, napi_value object, const std::string &key, uint32_t maxLen)
{
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, object, key.c_str(), &hasProperty));
    if (!hasProperty) {
        SGLOGE("no %{public}s param", key.c_str());
        return "";
    }
    napi_value value = nullptr;
    NAPI_CALL(env, napi_get_named_property(env, object, key.c_str(), &value));
    if (value == nullptr) {
        SGLOGE("get %{public}s failed", key.c_str());
        return "";
    }
    size_t len = maxLen;
    std::vector<char> str(len + 1, '\0');
    napi_value result = GetString(env, value, key, str.data(), len);
    if (result == nullptr) {
        SGLOGE("get %{public}s failed", key.c_str());
        return "";
    }
    return std::string{str.data()};
}
#ifndef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
static bool ParseModelRule(const napi_env &env, napi_value napiValue, ModelRule &modelRule)
{
    napi_valuetype type = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, napiValue, &type), false);
    if (type != napi_object) {
        std::string errMsg = "Parameter error. type of param ModelRule is not object.";
        SGLOGE("Parameter error. type of param ModelRule is not object.");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, errMsg));
        return false;
    }
    char modelName[MODEL_NAME_MAX_LEN] = {0};
    size_t len = MODEL_NAME_MAX_LEN;
    if (ParseString(env, napiValue, "modelName", modelName, len) == nullptr) {
        std::string errMsg = "Parameter error. type of param ModelRule.modelName is not string.";
        SGLOGE("Parameter error. type of param ModelRule.modelName is not string.");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, errMsg));
        return false;
    }
    modelRule.modelName = std::string(modelName);
    modelRule.param = ParseOptionalString(env, napiValue, "param", PARAM_MAX_LEN);
    return true;
}
#endif

static napi_value NapiGetModelResult(napi_env env, napi_callback_info info)
{
#ifndef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
    size_t argc = NAPI_GET_MODEL_RESULT_ARGS_CNT;
    napi_value argv[NAPI_GET_MODEL_RESULT_ARGS_CNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != NAPI_GET_MODEL_RESULT_ARGS_CNT) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "arguments count is not expected"));
        return nullptr;
    }
    uint32_t modelId = 0;
    ModelRule modelRule = {};
    if (!ParseModelRule(env, argv[0], modelRule)) {
        return nullptr;
    }
    if (ParseModelId(env, modelRule.modelName, modelId) == nullptr) {
        return nullptr;
    }

    RequestSecurityModelResultContext *context = new (std::nothrow) RequestSecurityModelResultContext();
    if (context == nullptr) {
        napi_throw(env, GenerateBusinessError(env, NULL_OBJECT, "context new failed, no memory left."));
        return nullptr;
    }
    context->modelId = modelId;
    context->param = modelRule.param;
    napi_value promise = nullptr;
    if (napi_create_promise(env, &context->deferred, &promise) != napi_ok) {
        delete context;
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM));
        return nullptr;
    }
    napi_value resourceName = NapiCreateString(env, "NapiGetModelResult");
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, RequestSecurityModelResultExecute,
        RequestSecurityModelResultComplete, static_cast<void *>(context), &context->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, context->asyncWork));
    return promise;
#else
    napi_throw(env, GenerateBusinessError(env, API_SUPPORT_ERROR));
    SGLOGE("API is not supported.");
    return nullptr;
#endif
}

static napi_value ParsePolicyFileInfo(napi_env env, napi_value object, NapiSecurityPolicyFileInfo *context)
{
    napi_valuetype type = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, object, &type));
    if (type != napi_object) {
        GenerateBusinessError(env, BAD_PARAM, "type of param eventInfo is not object");
        return nullptr;
    }

    if (ParseInt32(env, object, "fd", context->fd) == nullptr) {
        return nullptr;
    }
    char name[FILE_NAME_MAX_LEN] = {0};
    size_t len = FILE_NAME_MAX_LEN;
    if (ParseString(env, object, "name", name, len) == nullptr) {
        return nullptr;
    }
    context->fileName = name;
    return NapiCreateInt32(env, SUCCESS);
}

static void UpdatePolicyExecute(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    auto *context = static_cast<NapiSecurityPolicyFileInfo *>(data);
    SecurityConfigUpdateInfo policyInfo(context->fd, context->fileName);
    context->ret = SecurityGuardSdkAdaptor::ConfigUpdate(policyInfo);
    if (context->ret != SUCCESS) {
        SGLOGE("update policy file error, code=%{public}d", context->ret);
        return ;
    }
}

static void UpdatePolicyComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        return;
    }
    auto *context = static_cast<NapiSecurityPolicyFileInfo *>(data);
    napi_value result {};
    result = GenerateBusinessError(env, context->ret);
    if (context->ret == SUCCESS) {
        napi_resolve_deferred(env, context->deferred, result);
    } else {
        napi_reject_deferred(env, context->deferred, result);
    }
    napi_delete_async_work(env, context->asyncWork);
    delete context;
}

static napi_value NapiUpdatePolicyFile(napi_env env, napi_callback_info info)
{
    size_t argc = NAPI_UPDATE_POLICY_FILE_ARGS_CNT;
    napi_value argv[NAPI_UPDATE_POLICY_FILE_ARGS_CNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != NAPI_UPDATE_POLICY_FILE_ARGS_CNT) {
        SGLOGE("update policy file arg count is not expected");
        std::string msg = "update policy arguments count is not expected";
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, msg));
        return nullptr;
    }

    NapiSecurityPolicyFileInfo *context = new (std::nothrow) NapiSecurityPolicyFileInfo();
    if (context == nullptr) {
        napi_throw(env, GenerateBusinessError(env, NULL_OBJECT, "context new failed, no memory left."));
        return nullptr;
    }
    napi_value ret = ParsePolicyFileInfo(env, argv[0], context);
    if (ret == nullptr) {
        SGLOGE("policy file parse error");
        delete context;
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM));
        return nullptr;
    }

    napi_value promise = nullptr;
    if (napi_create_promise(env, &context->deferred, &promise) != napi_ok) {
        delete context;
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM));
        return nullptr;
    }
    napi_value resourceName = NapiCreateString(env, "NapiUpdatePolicyFile");
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, UpdatePolicyExecute,
        UpdatePolicyComplete, static_cast<void *>(context), &context->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, context->asyncWork));

    return promise;
}

static bool ParseEventForNotifyCollector(napi_env env, napi_value object,
    OHOS::Security::SecurityCollector::Event &event)
{
    napi_valuetype type = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, object, &type), false);
    if (type != napi_object) {
        SGLOGE("type of param event is not object");
        return false;
    }
    int64_t eventId = 0;
    if (ParseInt64(env, object, "eventId", eventId) == nullptr) {
        return false;
    }

    event.eventId = eventId;
    event.version = ParseOptionalString(env, object, "version", VERSION_MAX_LEN);
    event.content = ParseOptionalString(env, object, "content", CONTENT_MAX_LEN);
    event.extra = ParseOptionalString(env, object, "param", EXTRA_MAX_LEN);
    SGLOGI("param extra end");
    return true;
}

static napi_value NapiStartSecurityEventCollector(napi_env env, napi_callback_info info)
{
    SGLOGD("in NapiStartSecurityEventCollector");
    size_t argc = NAPI_START_COLLECTOR_ARGS_CNT;
    napi_value argv[NAPI_START_COLLECTOR_ARGS_CNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != NAPI_START_COLLECTOR_ARGS_CNT && argc != NAPI_START_COLLECTOR_ARGS_CNT - 1) {
        SGLOGE("notify arguments count is not expected");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM));
        return nullptr;
    }

    OHOS::Security::SecurityCollector::Event event{};
    if (!ParseEventForNotifyCollector(env, argv[0], event)) {
        SGLOGE("notify context parse error");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "param event error"));
        return nullptr;
    }
    NotifyCollectorContext context{event, -1};

    if (argc == NAPI_START_COLLECTOR_ARGS_CNT) {
        napi_valuetype type;
        NAPI_CALL(env, napi_typeof(env, argv[1], &type));
        if (type != napi_number) {
            SGLOGE("type of param is not number");
            napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "param not number"));
            return nullptr;
        }
        int64_t duration = -1;
        napi_get_value_int64(env, argv[1], &duration);
        if (duration <= 0) {
            SGLOGE("duration of param is invalid");
            napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "param invalid"));
            return nullptr;
        }
        context.duration = duration;
    }

    int32_t code = SecurityGuardSdkAdaptor::StartCollector(context.event, context.duration);
    if (code != SUCCESS) {
        SGLOGE("notify error, code=%{public}d", code);
        napi_throw(env, GenerateBusinessError(env, code));
    }
    return NapiCreateInt32(env, ConvertToJsErrCode(code));
}

static napi_value NapiStopSecurityEventCollector(napi_env env, napi_callback_info info)
{
    SGLOGD("in NapiStopSecurityEventCollector");
    size_t argc = NAPI_STOP_COLLECTOR_ARGS_CNT;
    napi_value argv[NAPI_STOP_COLLECTOR_ARGS_CNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != NAPI_STOP_COLLECTOR_ARGS_CNT) {
        SGLOGE("notify arguments count is not expected");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM));
        return nullptr;
    }

    OHOS::Security::SecurityCollector::Event event{};
    if (!ParseEventForNotifyCollector(env, argv[0], event)) {
        SGLOGE("notify context parse error");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "param event error"));
        return nullptr;
    }

    int32_t code = SecurityGuardSdkAdaptor::StopCollector(event);
    if (code != SUCCESS) {
        SGLOGE("notify error, code=%{public}d", code);
        napi_throw(env, GenerateBusinessError(env, code));
    }
    return NapiCreateInt32(env, ConvertToJsErrCode(code));
}

static napi_valuetype GetValueType(const napi_env env, const napi_value& value)
{
    napi_valuetype valueType = napi_undefined;
    napi_status ret = napi_typeof(env, value, &valueType);
    if (ret != napi_ok) {
        SGLOGE("failed to parse the type of napi value.");
    }
    return valueType;
}

static bool IsValueTypeValid(const napi_env env, const napi_value& object,
    const napi_valuetype typeName)
{
    napi_valuetype valueType = GetValueType(env, object);
    if (valueType != typeName) {
        SGLOGE("napi value type not match: valueType=%{public}d, typeName=%{public}d.", valueType, typeName);
        return false;
    }
    return true;
}

static bool CheckValueIsArray(const napi_env env, const napi_value& object)
{
    if (!IsValueTypeValid(env, object, napi_valuetype::napi_object)) {
        return false;
    }
    bool isArray = false;
    napi_status ret = napi_is_array(env, object, &isArray);
    if (ret != napi_ok) {
        SGLOGE("failed to check array napi value.");
    }
    return isArray;
}

static SecurityEventRuler ParseSecurityEventRuler(const napi_env env, const napi_value& object)
{
    SecurityEventRuler rule {};
    if (!IsValueTypeValid(env, object, napi_valuetype::napi_object)) {
        return rule;
    }
    napi_value result = nullptr;
    int64_t eventId = 0;
    result = ParseInt64(env, object, "eventId", eventId);
    if (result == nullptr) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "Parameter error. The eventId error."));
        SGLOGE("get conditions beginTime error");
        return rule;
    }

    std::string beginTime = "";
    result = GetConditionsTime(env, object, "beginTime", beginTime);
    if (result == nullptr) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "Parameter error. The beginTime error."));
        SGLOGE("get conditions beginTime error");
        return rule;
    }

    std::string endTime = "";
    result = GetConditionsTime(env, object, "endTime", endTime);
    if (result == nullptr) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "Parameter error. The endTime error."));
        SGLOGE("get conditions endTime error");
        return rule;
    }
    if (!beginTime.empty() && !endTime.empty() && beginTime > endTime) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "Parameter error. The time matching error."));
        SGLOGE("Time matching error");
        return rule;
    }

    std::string param = ParseOptionalString(env, object, "param", EXTRA_MAX_LEN);
    return { eventId, beginTime, endTime, param };
}

static int32_t ParseSecurityEventRulers(const napi_env env, napi_value& object, std::vector<SecurityEventRuler>& rulers)
{
    if (!CheckValueIsArray(env, object)) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "Parameter error. The type of rulers must be array."));
        return BAD_PARAM;
    }
    uint32_t len = 0;
    napi_status status = napi_get_array_length(env, object, &len);
    if (status != napi_ok) {
        return BAD_PARAM;
    }
    napi_value element;
    for (uint32_t i = 0; i < len; i++) {
        status = napi_get_element(env, object, i, &element);
        if (status != napi_ok) {
            return BAD_PARAM;
        }
        if (IsValueTypeValid(env, element, napi_valuetype::napi_object)) {
            auto ruler = ParseSecurityEventRuler(env, element);
            rulers.emplace_back(ruler);
        }
    }
    return SUCCESS;
}

template<typename T>
static typename std::unordered_map<napi_ref, std::pair<pid_t, std::shared_ptr<T>>>::iterator CompareAndReturnCacheItem(
    const napi_env env, napi_value& standard,
    std::unordered_map<napi_ref, std::pair<pid_t, std::shared_ptr<T>>>& resources)
{
    bool found = false;
    napi_status status;
    auto iter = resources.begin();
    for (; iter != resources.end(); iter++) {
        if (iter->second.first != syscall(SYS_gettid)) { // avoid error caused by vm run in multi-thread
            continue;
        }
        napi_value val = nullptr;
        status = napi_get_reference_value(env, iter->first, &val);
        if (status != napi_ok) {
            continue;
        }
        status = napi_strict_equals(env, standard, val, &found);
        if (status != napi_ok) {
            continue;
        }
        if (found) {
            break;
        }
    }
    return iter;
}

static int32_t ParseQueryParamsAndCreateContext(napi_env env, napi_callback_info info,
    std::vector<SecurityEventRuler> &rules, QuerySecurityEventContext *&context)
{
    size_t argc = NAPI_QUERY_SECURITY_EVENT_ARGS_CNT;
    napi_value argv[NAPI_QUERY_SECURITY_EVENT_ARGS_CNT] = {nullptr};
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), BAD_PARAM);
    if (argc != NAPI_QUERY_SECURITY_EVENT_ARGS_CNT) {
        SGLOGE("query arguments count is not expected");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM));
        return BAD_PARAM;
    }
    size_t index = 0;
    if (auto ret = ParseSecurityEventRulers(env, argv[index++], rules); ret != SUCCESS) {
        SGLOGE("failed to parse query rules, result code is %{public}d.", ret);
        return BAD_PARAM;
    }
    if (IsValueTypeValid(env, argv[index], napi_valuetype::napi_null) ||
        IsValueTypeValid(env, argv[index], napi_valuetype::napi_undefined)) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "Parameter error. The type of must querier be Querier."));
        SGLOGE("querier is null or undefined.");
        return BAD_PARAM;
    }
    context = new (std::nothrow) QuerySecurityEventContext;
    if (context == nullptr) {
        return NULL_OBJECT;
    }
    context->env = env;
    context->threadId = getproctid();
    napi_create_reference(env, argv[index], 1, &context->ref);
    return SUCCESS;
}

static napi_value NapiQuerySecurityEvent(napi_env env, napi_callback_info info)
{
    std::vector<SecurityEventRuler> rules;
    QuerySecurityEventContext *context = nullptr;
    int32_t ret = ParseQueryParamsAndCreateContext(env, info, rules, context);
    if (ret != SUCCESS || context == nullptr) {
        return nullptr;
    }
    auto querier = std::make_shared<NapiSecurityEventQuerier>(context, [] (const napi_env env, const napi_ref ref) {
            napi_value querier = nullptr;
            napi_get_reference_value(env, ref, &querier);
            std::unique_lock<std::mutex> lock(g_queryMutex);
            auto iter = CompareAndReturnCacheItem<NapiSecurityEventQuerier>(env, querier, queriers);
            if (iter != queriers.end()) {
                queriers.erase(iter->first);
                NapiRequestDataManager::GetInstance().DelDataCallback(env);
            }
            SGLOGI("NapiSecurityEventQuerier OnFinsh Callback end.");
        });
    int32_t code = SecurityGuardSdkAdaptor::QuerySecurityEvent(rules, querier);
    if (code != SUCCESS) {
        SGLOGE("query error, code=%{public}d", code);
        delete context;
        napi_throw(env, GenerateBusinessError(env, code));
        return nullptr;
    }
    std::unique_lock<std::mutex> lock(g_queryMutex);
    queriers[context->ref] = std::make_pair(context->threadId, querier);
    NapiRequestDataManager::GetInstance().AddDataCallback(env);
    SGLOGI("NapiQuerySecurityEvent end.");
    return nullptr;
}

static bool GetCallbackProperty(napi_env env, napi_value obj, napi_ref &property, int argNum)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, obj, &valueType), false);
    if ((valueType == napi_undefined) || (valueType == napi_null)) {
        SGLOGI("the callback is undefined or null");
        return false;
    } else if (valueType == napi_function) {
        NAPI_CALL_BASE(env, napi_create_reference(env, obj, argNum, &property), false);
        return true;
    }
    SGLOGE("the callback is not a napi_function");
    return false;
}

static bool GetStringProperty(napi_env env, napi_value obj, std::string &property)
{
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, obj, &valuetype), false);
    if (valuetype != napi_string) {
        return false;
    }

    size_t propLen;
    NAPI_CALL_BASE(env, napi_get_value_string_utf8(env, obj, nullptr, 0, &propLen), false);
    if (propLen > ALL_PROPERTY_MAX_LEN) {
        SGLOGE("Parameter error. param is too long");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "Parameter error. param is too long"));
        return false;
    }
    property.reserve(propLen + 1);
    property.resize(propLen);
    NAPI_CALL_BASE(env, napi_get_value_string_utf8(env, obj, property.data(), propLen + 1, &propLen), false);
    return true;
}

static napi_value WrapVoidToJS(napi_env env)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

static napi_value ParseAuditEventInfo(const napi_env &env, napi_value napi, SubscribeEventInfo &eventInfo)
{
    napi_valuetype type = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, napi, &type), nullptr);
    if (type != napi_object) {
        std::string errMsg = "Parameter error. type of param AuditEventInfo is not object.";
        SGLOGE("Parameter error. type of param AuditEventInfo is not object.");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, errMsg));
        return nullptr;
    }
    int64_t eventId = 0;
    if (ParseInt64(env, napi, "eventId", eventId) == nullptr) {
        std::string errMsg = "Parameter error. type of param AuditEventInfo.eventId is not number.";
        SGLOGE("Parameter error. type of param AuditEventInfo.eventId is not number.");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, errMsg));
        return nullptr;
    }
    eventInfo.eventId = eventId;
    return NapiCreateInt64(env, ConvertToJsErrCode(SUCCESS));
}

static bool ParseSubscribeForEventOccur(const napi_env &env, const std::string &type,
    SubscribeCBInfo *info, napi_value napiValue)
{
    if (type != "securityEventOccur") {
        std::string errMsg = "Parameter error. The param of type must be securityEventOccur.";
        SGLOGE("Parameter error. The param of type must be securityEventOccur.");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, errMsg));
        return false;
    }
    SubscribeEventInfo eventInfo;
    if (ParseAuditEventInfo(env, napiValue, eventInfo) == nullptr) {
        return false;
    }
    info->events.eventId = eventInfo.eventId;
    return true;
}

static bool ParseSubscribeParam(const napi_env &env, napi_callback_info cbInfo, SubscribeCBInfo *info,
    napi_value *thisVar)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_get_cb_info(env, cbInfo, &argc, argv, thisVar, NULL);
    if (argc != ARGS_SIZE_THREE) {
        SGLOGE("Parameter error. The parameters number must be three");
        std::string errMsg = "Parameter error. The parameters number must be three";
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, errMsg));
        return false;
    }
    if (!GetCallbackProperty(env, argv[argc - 1], info->callbackRef, 1)) {
        SGLOGE("Get callbackRef failed");
        std::string errMsg = "Parameter error. The type of arg " + std::to_string(argc) + " must be function";
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, errMsg));
        return false;
    }
    std::string type;
    if (!GetStringProperty(env, argv[PARAMZERO], type)) {
        SGLOGE("Get type failed");
        std::string errMsg = "The type of arg 1 must be string";
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, errMsg));
        return false;
    }
    return ParseSubscribeForEventOccur(env, type, info, argv[PARAMONE]);
}

static bool IsCurrentThread(std::thread::id threadId)
{
    std::thread::id currentThread = std::this_thread::get_id();
    if (threadId != currentThread) {
        SGLOGE("napi_ref can not be compared,different threadId");
        return false;
    }
    return true;
}

static bool CompareOnAndOffRef(const napi_env env, napi_ref subscriberRef, napi_ref unsubscriberRef,
    std::thread::id threadId)
{
    if (!IsCurrentThread(threadId)) {
        return false;
    }
    napi_value subscriberCallback;
    napi_get_reference_value(env, subscriberRef, &subscriberCallback);
    napi_value unsubscriberCallback;
    napi_get_reference_value(env, unsubscriberRef, &unsubscriberCallback);
    bool result = false;
    napi_strict_equals(env, subscriberCallback, unsubscriberCallback, &result);
    return result;
}

static bool IsSubscribeInMap(napi_env env, SubscribeCBInfo *info)
{
    std::lock_guard<std::mutex> lock(g_subscribeMutex);
    auto subscribe = g_subscribers.find(env);
    if (subscribe == g_subscribers.end()) {
        return false;
    }
    auto it = subscribe->second.begin();
    while (it != subscribe->second.end()) {
        if (CompareOnAndOffRef(env, (*it)->callbackRef, info->callbackRef, (*it)->threadId)) {
            return true;
        }
        it++;
    }
    return false;
}

static napi_value ParseUnsubscriberAuditEventInfo(const napi_env &env, napi_value napi, UnsubscribeCBInfo *asyncContext)
{
    napi_valuetype type = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, napi, &type), nullptr);
    if (type != napi_object) {
        std::string errMsg = "Parameter error. type of param AuditEventInfo is not object.";
        SGLOGE("Parameter error. type of param AuditEventInfo is not object.");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, errMsg));
        return nullptr;
    }
    int64_t eventId = 0;
    if (ParseInt64(env, napi, "eventId", eventId) == nullptr) {
        std::string errMsg = "Parameter error. type of param AuditEventInfo.eventId is not number.";
        SGLOGE("Parameter error. type of param AuditEventInfo.eventId is not number.");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, errMsg));
        return nullptr;
    }
    asyncContext->events.eventId = eventId;
    return NapiCreateInt64(env, ConvertToJsErrCode(SUCCESS));
}

static bool ParseParaToUnsubscriber(const napi_env &env, napi_callback_info cbInfo, UnsubscribeCBInfo *asyncContext,
    napi_value *thisVar, size_t &argc)
{
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_get_cb_info(env, cbInfo, &argc, argv, thisVar, NULL);
    if (argc != ARGS_SIZE_THREE && argc != ARGS_SIZE_TWO) {
        SGLOGE("Parameter error. The parameters number must be three or two");
        std::string errMsg = "Parameter error. The parameters number must be three or two";
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, errMsg));
        return false;
    }
    if (argc == ARGS_SIZE_THREE && !GetCallbackProperty(env, argv[argc - 1], asyncContext->callbackRef, 1)) {
        SGLOGE("Get callbackRef failed");
        std::string errMsg = "Parameter error. The type of arg " + std::to_string(argc) + " must be function";
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, errMsg));
        return false;
    }
    std::string type;
    if (!GetStringProperty(env, argv[PARAMZERO], type)) {
        SGLOGE("Get type failed");
        std::string errMsg = "Parameter error. The type of arg 1 must be string";
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, errMsg));
        return false;
    }
    if (type != "securityEventOccur") {
        SGLOGE("type err");
        std::string errMsg = "Parameter error. arg 1 must be securityEventOccur";
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, errMsg));
        return false;
    }
    if (ParseUnsubscriberAuditEventInfo(env, argv[PARAMONE], asyncContext) == nullptr) {
        return false;
    }
    return true;
}

static napi_value GenerateEvent(napi_env env, const NapiSecurityEvent &event)
{
    napi_value ret = NapiCreateObject(env);
    if (ret == nullptr) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "napi create object error ."));
    }
    napi_value eventId = NapiCreateInt64(env, event.eventId);
    napi_value version = NapiCreateString(env, event.version);
    napi_value content = NapiCreateString(env, event.content);

    napi_set_named_property(env, ret, NAPI_EVENT_EVENT_ID_ATTR, eventId);
    napi_set_named_property(env, ret, NAPI_EVENT_VERSION_ATTR, version);
    napi_set_named_property(env, ret, NAPI_EVENT_CONTENT_ATTR, content);
    return ret;
}

static bool InitUvWorkCallbackEnv(const SubscriberOAWorker &subscriberOAWorkerData, napi_handle_scope *scope)
{
    napi_open_handle_scope(subscriberOAWorkerData.env, scope);
    if (scope == nullptr) {
        SGLOGE("fail to open scope");
        return false;
    }
    return true;
}

static void SendEventOnSecEventsChanged(const SubscriberOAWorker &subscriberOAWorkerData)
{
    auto task = [subscriberOAWorkerData]() {
        napi_handle_scope scope = nullptr;
        if (!InitUvWorkCallbackEnv(subscriberOAWorkerData, &scope)) {
            return;
        }
        bool isFound = false;
        {
            std::lock_guard<std::mutex> lock(g_subscribeMutex);
            SubscriberPtr *subscriber = subscriberOAWorkerData.subscriber;
            for (auto subscriberInstance : g_subscribers) {
                isFound = std::any_of(subscriberInstance.second.begin(), subscriberInstance.second.end(),
                    [subscriber](const SubscribeCBInfo *item) {
                        return item->subscriber.get() == subscriber;
                    });
                if (isFound) {
                    SGLOGI("subscriber has been found.");
                    break;
                }
            }
        }
        if (isFound) {
            napi_value result[ARGS_SIZE_ONE] = {nullptr};
            result[PARAMZERO] = GenerateEvent(subscriberOAWorkerData.env, subscriberOAWorkerData.event);
            napi_value undefined = nullptr;
            napi_get_undefined(subscriberOAWorkerData.env, &undefined);
            napi_value callback = nullptr;
            napi_get_reference_value(subscriberOAWorkerData.env, subscriberOAWorkerData.ref, &callback);
            napi_value resultOut = nullptr;
            napi_status ok = napi_call_function(subscriberOAWorkerData.env, undefined, callback, ARGS_SIZE_ONE,
                &result[0], &resultOut);
            SGLOGI("isOk=%{public}d", ok);
        }
        napi_close_handle_scope(subscriberOAWorkerData.env, scope);
    };
    napi_send_event(subscriberOAWorkerData.env, task, napi_eprio_high,
        "SecurityGuardNapi::SendEventOnSecEventsChanged");
}

static int32_t OnNotifyEvent(const Event &event, napi_env env, napi_ref ref, SubscriberPtr *subscriber)
{
    SGLOGI("OnNotify");
    SubscriberOAWorker subscriberOAWorkerData {};
    subscriberOAWorkerData.event.eventId = event.eventId;
    subscriberOAWorkerData.event.version = event.version;
    subscriberOAWorkerData.event.content = event.content;
    subscriberOAWorkerData.event.timestamp = event.timestamp;
    subscriberOAWorkerData.env = env;
    subscriberOAWorkerData.ref = ref;
    subscriberOAWorkerData.subscriber = subscriber;
    SendEventOnSecEventsChanged(subscriberOAWorkerData);
    return 0;
}

class SubscriberPtr : public ICollectorSubscriber {
public:
    explicit SubscriberPtr(const Event &event) : ICollectorSubscriber(event, -1, false, "securityGroup") {};
    ~SubscriberPtr() override = default;

    int32_t OnNotify(const Event &event) override
    {
        if (OnNotifyEvent(event, env_, ref_, this) != 0) {
            return -1;
        }
        return 0;
    };
    void SetEnv(const napi_env &env) { env_ = env; }
    void SetCallbackRef(const napi_ref &ref) { ref_ = ref; }
private:
    napi_env env_ = nullptr;
    napi_ref ref_ = nullptr;
};

static napi_value Subscribe(napi_env env, napi_callback_info cbInfo)
{
    SubscribeCBInfo *info = new (std::nothrow) SubscribeCBInfo(env, std::this_thread::get_id());
    if (info == nullptr) {
        napi_throw(env, GenerateBusinessError(env, NULL_OBJECT, "No memory!"));
        return nullptr;
    }

    napi_value thisVar = nullptr;
    if (!ParseSubscribeParam(env, cbInfo, info, &thisVar)) {
        delete info;
        SGLOGE("Parse subscribe failed");
        return nullptr;
    }
    info->subscriber = std::make_shared<SubscriberPtr>(info->events);
    info->subscriber->SetEnv(env);
    info->subscriber->SetCallbackRef(info->callbackRef);
    if (IsSubscribeInMap(env, info)) {
        SGLOGE("Current callback ref is existed");
        delete info;
        return WrapVoidToJS(env);
    }
    int32_t errCode = SecurityGuardSdkAdaptor::Subscribe(info->subscriber);
    if (errCode != 0) {
        delete info;
        napi_throw(env, GenerateBusinessError(env, errCode, "Subscribe failed!"));
        return WrapVoidToJS(env);
    } else {
        std::lock_guard<std::mutex> lock(g_subscribeMutex);
        g_subscribers[env].emplace_back(info);
    }
    return WrapVoidToJS(env);
}

static void AllUnsubscribeSync(napi_env env, UnsubscribeCBInfo *unsubscribeCBInfo)
{
    std::lock_guard<std::mutex> lock(g_subscribeMutex);
    auto subscribe = g_subscribers.find(env);
    if (subscribe == g_subscribers.end()) {
        return;
    }
    auto i = subscribe->second.begin();
    while (i != subscribe->second.end()) {
        if ((*i)->events.eventId != unsubscribeCBInfo->events.eventId) {
            i++;
            continue;
        }
        int errCode = SecurityGuardSdkAdaptor::Unsubscribe((*i)->subscriber);
        if (errCode != 0) {
            std::string errMsg = "unsubscrube failed";
            napi_throw(env, GenerateBusinessError(env, errCode, errMsg));
            return;
        }
        delete (*i);
        i = subscribe->second.erase(i);
    }
    if (subscribe->second.empty()) {
        g_subscribers.erase(subscribe->first);
    }
}

static void UnsubscribeSync(napi_env env, UnsubscribeCBInfo *unsubscribeCBInfo)
{
    std::lock_guard<std::mutex> lock(g_subscribeMutex);
    auto subscribe = g_subscribers.find(env);
    if (subscribe == g_subscribers.end()) {
        return;
    }
    auto item = subscribe->second.begin();
    while (item != subscribe->second.end()) {
        if ((unsubscribeCBInfo->callbackRef != nullptr) &&
            (!CompareOnAndOffRef(env, (*item)->callbackRef, unsubscribeCBInfo->callbackRef, (*item)->threadId))) {
            item++;
            continue;
        }
        int errCode = SecurityGuardSdkAdaptor::Unsubscribe((*item)->subscriber);
        if (errCode != 0) {
            std::string errMsg = "unsubscrube failed";
            napi_throw(env, GenerateBusinessError(env, errCode, errMsg));
            return;
        }
        delete (*item);
        item = subscribe->second.erase(item);
        if (unsubscribeCBInfo->callbackRef != nullptr) {
            break;
        }
    }
    if (subscribe->second.empty()) {
        g_subscribers.erase(subscribe->first);
    }
}

static napi_value Unsubscribe(napi_env env, napi_callback_info cbInfo)
{
    UnsubscribeCBInfo *unsubscribeCBInfo = new (std::nothrow) UnsubscribeCBInfo(env, std::this_thread::get_id());
    if (unsubscribeCBInfo == nullptr) {
        SGLOGE("insufficient memory for unsubscribeCBInfo!");
        napi_throw(env, GenerateBusinessError(env, NULL_OBJECT, "No memory!"));
        return WrapVoidToJS(env);
    }
    unsubscribeCBInfo->callbackRef = nullptr;
    unsubscribeCBInfo->throwErr = true;

    napi_value thisVar = nullptr;
    size_t argc = ARGS_SIZE_THREE;
    if (!ParseParaToUnsubscriber(env, cbInfo, unsubscribeCBInfo, &thisVar, argc)) {
        delete unsubscribeCBInfo;
        SGLOGE("Parse unsubscribe failed");
        return nullptr;
    }
    if (argc == ARGS_SIZE_THREE) {
        UnsubscribeSync(env, unsubscribeCBInfo);
    } else {
        AllUnsubscribeSync(env, unsubscribeCBInfo);
    }
    SGLOGI("UnsubscribeSync success");
    delete unsubscribeCBInfo;
    return WrapVoidToJS(env);
}

EXTERN_C_START
static napi_value SecurityGuardNapiRegister(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("startSecurityEventCollector", NapiStartSecurityEventCollector),
        DECLARE_NAPI_FUNCTION("stopSecurityEventCollector", NapiStopSecurityEventCollector),
        DECLARE_NAPI_FUNCTION("querySecurityEvent", NapiQuerySecurityEvent),
        DECLARE_NAPI_FUNCTION("reportSecurityEvent", NapiReportSecurityInfo),
        DECLARE_NAPI_FUNCTION("on", Subscribe),
        DECLARE_NAPI_FUNCTION("off", Unsubscribe),
        DECLARE_NAPI_FUNCTION("getModelResult", NapiGetModelResult),
        DECLARE_NAPI_FUNCTION("updatePolicyFile", NapiUpdatePolicyFile),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}
EXTERN_C_END

static napi_module g_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = SecurityGuardNapiRegister,
    .nm_modname = "security.securityGuard",
    .nm_priv = reinterpret_cast<void *>(0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&g_module);
}