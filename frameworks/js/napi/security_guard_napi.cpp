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

#include <future>
#include <unistd.h>
#include <syscall.h>
#include <unordered_map>

#include "napi_request_data_manager.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_napi.h"
#include "security_guard_sdk_adaptor.h"
#include "uv.h"

#include "securec.h"

using namespace OHOS::Security::SecurityGuard;

constexpr int NAPI_REPORT_EVENT_INFO_ARGS_CNT = 1;
constexpr int NAPI_REQUEST_SECURITY_EVENT_INFO_ARGS_CNT = 3;
constexpr int NAPI_REQUEST_SECURITY_EVENT_INFO_CALLBACK_ARGS_CNT = 2;
constexpr int NAPI_REQUEST_SECURITY_MODEL_RESULT_ARGS_MIN_CNT = 2;
constexpr int NAPI_REQUEST_SECURITY_MODEL_RESULT_ARGS_MAX_CNT = 3;
constexpr int NAPI_SET_MODEL_STATE_ARGS_MAX_CNT = 2;
constexpr int VERSION_MAX_LEN = 50;
constexpr int TIME_MAX_LEN = 20;
constexpr int CALLBACK_TYPE_MAX_LEN = 10;

static const std::unordered_map<int32_t, std::pair<int32_t, std::string>> g_errorStringMap = {
    { SUCCESS, { JS_ERR_SUCCESS, "The operation was successful" }},
    { NO_PERMISSION, { JS_ERR_NO_PERMISSION, "Check permission fail"} },
    { BAD_PARAM, { JS_ERR_BAD_PARAM, "Parameter error, please make sure using the correct value"} },
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

static napi_value NapiCreateInt64(const napi_env env, int32_t value)
{
    napi_value result = nullptr;
    napi_status status = napi_create_int64(env, value, &result);
    SGLOGI("create napi value of int64 type, value is %{public}d.", value);
    if (status != napi_ok || result == nullptr) {
        SGLOGE("failed to create napi value of int64 type.");
    }
    return result;
}

static napi_value NapiCreateInt32(const napi_env env, int32_t value)
{
    napi_value result = nullptr;
    napi_status status = napi_create_int32(env, value, &result);
    SGLOGI("create napi value of int32 type, value is %{public}d.", value);
    if (status != napi_ok || result == nullptr) {
        SGLOGE("failed to create napi value of int32 type.");
    }
    return result;
}

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

static napi_value GenerateBusinessError(napi_env env, int32_t code, std::string msg)
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

static napi_value ParseBool(napi_env env, napi_value object, bool &value)
{
    napi_valuetype type;
    NAPI_CALL(env, napi_typeof(env, object, &type));
    if (type != napi_boolean) {
        SGLOGE("type of param is not bool");
        return nullptr;
    }

    NAPI_CALL(env, napi_get_value_bool(env, object, &value));
    return NapiCreateInt32(env, ConvertToJsErrCode(SUCCESS));
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
        return nullptr;
    }

    napi_valuetype type;
    NAPI_CALL(env, napi_typeof(env, result, &type));
    if (type != napi_number) {
        SGLOGE("type of param %{public}s is not number", key.c_str());
        return nullptr;
    }

    NAPI_CALL(env, napi_get_value_int64(env, result, &value));
    return NapiCreateInt64(env, ConvertToJsErrCode(SUCCESS));
}

static napi_value ParseUint32(napi_env env, napi_value object, uint32_t &value)
{
    napi_valuetype type;
    NAPI_CALL(env, napi_typeof(env, object, &type));
    if (type != napi_number) {
        SGLOGE("type of param is not number");
        return nullptr;
    }

    NAPI_CALL(env, napi_get_value_uint32(env, object, &value));
    return NapiCreateInt32(env, ConvertToJsErrCode(SUCCESS));
}

static napi_value GetString(napi_env env, napi_value object, std::string key, char *value, size_t &maxLen)
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
    int32_t code = SecurityGuardSdkAdaptor::ReportSecurityInfo(eventInfo);
    if (code != SUCCESS) {
        SGLOGE("report eventInfo error, code=%{public}d", code);
    }
    return NapiCreateInt32(env, ConvertToJsErrCode(code));
}

static void DestoryWork(uv_work_t *work)
{
    if (work == nullptr) {
        return;
    }
    if (work->data != nullptr) {
        delete (reinterpret_cast<RequestSecurityEventInfoContext *>(work->data));
    }
    delete work;
}

static void DeleteRefIfFinish(napi_env env, napi_ref errCb, int32_t code)
{
    napi_value resArgv = nullptr;
    napi_value returnVal = nullptr;
    napi_value errCallback = nullptr;
    std::string errMsgStr = ConvertToJsErrMsg(code);
    napi_get_reference_value(env, errCb, &errCallback);
    napi_create_string_utf8(env, errMsgStr.c_str(), errMsgStr.length(), &resArgv);
    napi_call_function(env, nullptr, errCallback, 1, &resArgv, &returnVal);
    NapiRequestDataManager::GetInstance().DeleteContext(env);
}

static void DeleteRefIfFinish(napi_env env, napi_ref endCb, uint32_t status)
{
    if (status != 0) {
        return;
    }
    SGLOGE("call end");
    napi_value resArgv = nullptr;
    napi_value returnVal = nullptr;
    napi_value endCallback = nullptr;
    napi_get_reference_value(env, endCb, &endCallback);
    napi_status ret = napi_call_function(env, nullptr, endCallback, 1, &resArgv, &returnVal);
    if (ret != napi_ok) {
        SGLOGE("call end error, %{public}d", ret);
    }
    NapiRequestDataManager::GetInstance().DeleteContext(env);
}

static void DeleteRefIfFinish(RequestSecurityEventInfoContext *context)
{
    DeleteRefIfFinish(context->env, context->endCallback, context->status);
}

static napi_value GetConditionsEventIds(napi_env env, napi_value object,
    std::shared_ptr<RequestSecurityEventInfoContext> context)
{
    napi_value eventIds;
    napi_status status = napi_get_named_property(env, object, "eventIds", &eventIds);
    if (status != napi_ok || eventIds == nullptr) {
        SGLOGE("get %{public}s failed", "eventIds");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "param eventIds is not found"));
        return nullptr;
    }
    bool isArray = false;
    status = napi_is_array(env, eventIds, &isArray);
    if (status != napi_ok || !isArray) {
        SGLOGE("Invalid eventId list");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "param eventIds error"));
        return nullptr;
    }
    uint32_t arrayLength = 0;
    napi_get_array_length(env, eventIds, &arrayLength);
    for (uint32_t index = 0; index < arrayLength; index++) {
        napi_value jsEventId;
        int64_t eventId;
        napi_get_element(env, eventIds, index, &jsEventId);
        status = napi_get_value_int64(env, jsEventId, &eventId);
        if (status != napi_ok) {
            napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "param eventIds error"));
            return nullptr;
        }
        context->eventIds.emplace_back(eventId);
    }
    return NapiCreateInt32(env, SUCCESS);
}

static napi_value GetConditionsTime(napi_env env, napi_value object, std::string key, std::string &value)
{
    char time[TIME_MAX_LEN] = {0};
    size_t len = TIME_MAX_LEN;
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, object, key.c_str(), &hasProperty));
    if (!hasProperty) {
        SGLOGE("no %{publid}s param", key.c_str());
        return NapiCreateInt32(env, SUCCESS);
    }
    napi_value result;
    NAPI_CALL(env, napi_get_named_property(env, object, key.c_str(), &result));
    if (result == nullptr) {
        SGLOGE("get %{publid}s failed", key.c_str());
        return nullptr;
    }

    result = GetString(env, result, key.c_str(), time, len);
    if (result == nullptr) {
        SGLOGE("get %{publid}s failed", key.c_str());
        return nullptr;
    }
    value = time;
    return NapiCreateInt32(env, SUCCESS);
}

static napi_value ParseConditions(napi_env env, napi_value object,
    std::shared_ptr<RequestSecurityEventInfoContext> context)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, object, &type);
    if (status != napi_ok || type != napi_object) {
        SGLOGE("type of param eventInfo is not object");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "param conditions error"));
        return nullptr;
    }

    napi_value result = GetConditionsEventIds(env, object, context);
    if (result == nullptr) {
        SGLOGE("get conditions eventIds error");
        return nullptr;
    }

    std::string beginTime;
    result = GetConditionsTime(env, object, "beginTime", beginTime);
    if (result == nullptr) {
        SGLOGE("get conditions beginTime error");
        return nullptr;
    }

    std::string endTime;
    result = GetConditionsTime(env, object, "endTime", endTime);
    if (result == nullptr) {
        SGLOGE("get conditions endTime error");
        return nullptr;
    }

    context->conditions = "{\"eventId\":[";
    for (int64_t eventId : context->eventIds) {
        context->conditions += std::to_string(eventId) + ", ";
    }
    context->conditions = context->conditions.substr(0, context->conditions.length() - 1 - 1); // del the last comma
    context->conditions += "]";
    if (!beginTime.empty()) {
        context->conditions += ", \"beginTime\": \""+ beginTime + "\"";
    }
    if (!endTime.empty()) {
        context->conditions += ", \"endTime\": \""+ endTime + "\"";
    }
    context->conditions += "}";
    return NapiCreateInt32(env, SUCCESS);
}

static napi_value On(napi_env env, napi_callback_info info)
{
    SGLOGD("SG NAPI On called");
    size_t argc = NAPI_REQUEST_SECURITY_EVENT_INFO_CALLBACK_ARGS_CNT;
    napi_value argv[NAPI_REQUEST_SECURITY_EVENT_INFO_CALLBACK_ARGS_CNT] = {0};
    napi_status status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (status != napi_ok) {
        NapiRequestDataManager::GetInstance().DeleteContext(env);
        return nullptr;
    }
    if (argc != NAPI_REQUEST_SECURITY_EVENT_INFO_CALLBACK_ARGS_CNT) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "param count is not expecte"));
        NapiRequestDataManager::GetInstance().DeleteContext(env);
        return nullptr;
    }
    napi_valuetype napiType;
    napi_typeof(env, argv[0], &napiType);
    if (napiType != napi_string) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "the first param is not string"));
        NapiRequestDataManager::GetInstance().DeleteContext(env);
        return nullptr;
    }
    char type[CALLBACK_TYPE_MAX_LEN] = { 0 };
    size_t len = 0;
    napi_get_value_string_utf8(env, argv[0], type, CALLBACK_TYPE_MAX_LEN, &len);
    napi_typeof(env, argv[1], &napiType);
    if (napiType != napi_function) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "the second param is not function"));
        NapiRequestDataManager::GetInstance().DeleteContext(env);
        return nullptr;
    }

    auto context = NapiRequestDataManager::GetInstance().GetContext(env);
    if (strcmp("data", type) == 0) {
        napi_value cb = argv[1];
        napi_create_reference(env, cb, 1, &context->dataCallback);
    } else if (strcmp("end", type) == 0) {
        napi_value cb = argv[1];
        napi_create_reference(env, cb, 1, &context->endCallback);
    } else if (strcmp("error", type) == 0) {
        napi_value cb = argv[1];
        napi_create_reference(env, cb, 1, &context->errorCallback);
    } else {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "type mismatch"));
        NapiRequestDataManager::GetInstance().DeleteContext(env);
    };
    return nullptr;
}

static napi_value ParseCallback(napi_env env, napi_value object,
    std::shared_ptr<RequestSecurityEventInfoContext> context)
{
    napi_valuetype valueType;
    napi_typeof(env, object, &valueType);
    if (valueType != napi_function) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "callback is not function"));
        return nullptr;
    }
    napi_create_reference(env, object, 1, &context->ref);
    napi_value response = nullptr;
    napi_get_reference_value(env, context->ref, &response);
    napi_value returnVal = nullptr;
    napi_value resArgv = nullptr;
    napi_create_object(env, &resArgv);

    /* insert callback functions */
    const char* funName = "on";
    napi_value funcValue = nullptr;
    napi_create_function(env, funName, NAPI_AUTO_LENGTH, On, nullptr, &funcValue);
    napi_set_named_property(env, resArgv, funName, funcValue);
    napi_status ret = napi_call_function(env, nullptr, response, 1, &resArgv, &returnVal);
    if (ret != napi_ok) {
        SGLOGE("napi_call_function error");
        return nullptr;
    }
    return NapiCreateInt32(env, SUCCESS);
}

static void OnWork(uv_work_t *work, int status)
{
    if (work == nullptr || work->data == nullptr) {
        SGLOGE("work error");
        DestoryWork(work);
        return;
    }
    RequestSecurityEventInfoContext *context = reinterpret_cast<RequestSecurityEventInfoContext *>(work->data);
    if (context == nullptr || context->env == nullptr) {
        SGLOGE("context error");
        DestoryWork(work);
        return;
    }
    if (context->threadId != syscall(SYS_gettid)) {
        DeleteRefIfFinish(context);
        DestoryWork(work);
        return;
    }

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(context->env, &scope);
    if (scope == nullptr) {
        DeleteRefIfFinish(context);
        DestoryWork(work);
        return;
    }
    napi_value resArgv = nullptr;
    napi_create_string_utf8(context->env, context->info.c_str(), context->info.length(), &resArgv);
    napi_value returnVal = nullptr;
    napi_value dataCallback = nullptr;
    if (context->dataCallback == nullptr) {
        SGLOGE("callback is nullptr");
        DeleteRefIfFinish(context);
        napi_close_handle_scope(context->env, scope);
        DestoryWork(work);
        return;
    }
    napi_get_reference_value(context->env, context->dataCallback, &dataCallback);
    napi_status res = napi_call_function(context->env, nullptr, dataCallback, 1, &resArgv, &returnVal);
    if (res != napi_ok) {
        SGLOGE("failed to call data JS function, res=%{public}d", res);
    }
    DeleteRefIfFinish(context);
    napi_close_handle_scope(context->env, scope);
    DestoryWork(work);
}

static int32_t HandleRequestRiskDataCallback(std::shared_ptr<RequestSecurityEventInfoContext> context,
    std::string devId, std::string riskData, uint32_t status)
{
    RequestSecurityEventInfoContext *tmpContext = new (std::nothrow) RequestSecurityEventInfoContext();
    if (tmpContext == nullptr) {
        SGLOGE("new context error");
        DeleteRefIfFinish(context->env, context->endCallback, status);
        return NULL_OBJECT;
    }
    tmpContext->env = context->env;
    tmpContext->ref = context->ref;
    tmpContext->dataCallback = context->dataCallback;
    tmpContext->endCallback = context->endCallback;
    tmpContext->errorCallback = context->errorCallback;
    tmpContext->threadId = context->threadId;
    tmpContext->devId = devId;
    tmpContext->status = status;
    tmpContext->info = riskData;
    uv_loop_t *loop = nullptr;
    napi_status ret = napi_get_uv_event_loop(context->env, &loop);
    if (ret != napi_ok) {
        SGLOGE("failed to get uv_loop.");
        DeleteRefIfFinish(tmpContext);
        delete tmpContext;
        return NULL_OBJECT;
    }

    uv_work_t *work = new (std::nothrow) uv_work_t();
    if (work == nullptr) {
        SGLOGE("uv_work new failed, no memory left.");
        DeleteRefIfFinish(tmpContext);
        delete tmpContext;
        return NULL_OBJECT;
    }
    work->data = reinterpret_cast<void *>(tmpContext);
    uv_queue_work(loop, work, [] (uv_work_t *work) {}, OnWork);
    return SUCCESS;
}

static napi_value NapiRequestSecurityEventInfo(napi_env env, napi_callback_info info)
{
    size_t argc = NAPI_REQUEST_SECURITY_EVENT_INFO_ARGS_CNT;
    napi_value argv[NAPI_REQUEST_SECURITY_EVENT_INFO_ARGS_CNT] = {0};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    NAPI_ASSERT(env, argc == NAPI_REQUEST_SECURITY_EVENT_INFO_ARGS_CNT, "arguments count is not expected");

    uint32_t index = 0;
    char deviceIdArr[DEVICE_ID_MAX_LEN];
    size_t len = DEVICE_ID_MAX_LEN;
    napi_value result = GetString(env, argv[index], "deviceId", deviceIdArr, len);
    if (result == nullptr) {
        SGLOGE("parse deviceId error");
        return nullptr;
    }
    std::string deviceId(deviceIdArr);

    bool isExist = false;
    auto context = NapiRequestDataManager::GetInstance().GetContext(env, isExist);
    if (isExist) {
        napi_throw_error(env, nullptr, "another caller already exists");
        return nullptr;
    }
    context->env = env;
    context->threadId = syscall(SYS_gettid);
    index++;
    result = ParseConditions(env, argv[index], context);
    if (result == nullptr) {
        SGLOGE("parse conditions error");
        NapiRequestDataManager::GetInstance().DeleteContext(env);
        return nullptr;
    }
    index++;
    result = ParseCallback(env, argv[index], context);
    if (result == nullptr) {
        SGLOGE("parse callback error");
        NapiRequestDataManager::GetInstance().DeleteContext(env);
        return nullptr;
    }
    auto func = [context] (std::string &devId, std::string &riskData, uint32_t status) -> int32_t {
        return HandleRequestRiskDataCallback(context, devId, riskData, status);
    };

    int32_t code = SecurityGuardSdkAdaptor::RequestSecurityEventInfo(deviceId, context->conditions, func);
    if (code != SUCCESS) {
        SGLOGE("request eventInfo error, code=%{public}d.", code);
        DeleteRefIfFinish(env, context->errorCallback, code);
        napi_throw(env, GenerateBusinessError(env, code));
    }
    return nullptr;
}

static void RequestSecurityModelResultExecute(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    auto *context = static_cast<RequestSecurityModelResultContext *>(data);
    auto promise = std::make_shared<std::promise<SecurityModel>>();
    auto future = promise->get_future();
    auto func = [promise] (const std::string &devId, uint32_t modelId, const std::string &result) mutable -> int32_t {
        SecurityModel model = {
            .devId = devId,
            .modelId = modelId,
            .result = result
        };
        promise->set_value(model);
        return SUCCESS;
    };
    context->ret = SecurityGuardSdkAdaptor::RequestSecurityModelResult(context->deviceId, context->modelId, func);
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

static napi_value ParseModelId(napi_env env, napi_value object, uint32_t &modelId)
{
    if (ParseUint32(env, object, modelId) == nullptr) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM));
        return nullptr;
    }
    if (modelId != ModelIdType::ROOT_SCAN_MODEL_ID && modelId != ModelIdType::DEVICE_COMPLETENESS_MODEL_ID &&
        modelId != ModelIdType::PHYSICAL_MACHINE_DETECTION_MODEL_ID) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM,
            "Parameter error, please make sure using the correct model id"));
        return nullptr;
    }
    return NapiCreateInt32(env, SUCCESS);
}

static napi_value NapiRequestSecurityModelResult(napi_env env, napi_callback_info info)
{
    size_t argc = NAPI_REQUEST_SECURITY_MODEL_RESULT_ARGS_MAX_CNT;
    napi_value argv[NAPI_REQUEST_SECURITY_MODEL_RESULT_ARGS_MAX_CNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != NAPI_REQUEST_SECURITY_MODEL_RESULT_ARGS_MIN_CNT &&
        argc != NAPI_REQUEST_SECURITY_MODEL_RESULT_ARGS_MAX_CNT) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "arguments count is not expected"));
        return nullptr;
    }

    size_t index = 0;
    char deviceId[DEVICE_ID_MAX_LEN];
    size_t len = DEVICE_ID_MAX_LEN;
    if (GetString(env, argv[index], "deviceId", deviceId, len) == nullptr) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM));
        return nullptr;
    }

    index++;
    uint32_t modelId = 0;
    if (ParseModelId(env, argv[index], modelId) == nullptr) {
        return nullptr;
    }

    RequestSecurityModelResultContext *context = new (std::nothrow) RequestSecurityModelResultContext();
    if (context == nullptr) {
        napi_throw(env, GenerateBusinessError(env, NULL_OBJECT, "context new failed, no memory left."));
        return nullptr;
    }
    context->deviceId = deviceId;
    context->modelId = modelId;
    index++;
    if (index < argc) {
        napi_valuetype napiType;
        napi_typeof(env, argv[index], &napiType);
        if (napiType != napi_function) {
            napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "the third param is not function"));
            return nullptr;
        }
        napi_create_reference(env, argv[index], 1, &context->ref);
    }

    napi_value promise = nullptr;
    if (context->ref == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &context->deferred, &promise));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &promise));
    }
    napi_value resourceName = NapiCreateString(env, "NapiRequestSecurityModelResult");
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, RequestSecurityModelResultExecute,
        RequestSecurityModelResultComplete, static_cast<void *>(context), &context->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, context->asyncWork));
    return promise;
}

static napi_value EventIdTypeConstructor(napi_env env)
{
    napi_value eventIdType = nullptr;
    napi_value printerEventId = nullptr;
    NAPI_CALL(env, napi_create_object(env, &eventIdType));
    NAPI_CALL(env, napi_create_int64(env, EventIdType::PRINTER_EVENT_ID, &printerEventId));
    NAPI_CALL(env, napi_set_named_property(env, eventIdType, "PRINTER_EVENT_ID", printerEventId));
    return eventIdType;
}

static napi_value ModelIdTypeConstructor(napi_env env)
{
    napi_value modelIdType = nullptr;
    napi_value rsModelId = nullptr;
    napi_value dcModelId = nullptr;
    napi_value pmdModelId = nullptr;
    napi_value saModeltId = nullptr;
    NAPI_CALL(env, napi_create_object(env, &modelIdType));
    NAPI_CALL(env, napi_create_uint32(env, ModelIdType::ROOT_SCAN_MODEL_ID, &rsModelId));
    NAPI_CALL(env, napi_create_uint32(env, ModelIdType::DEVICE_COMPLETENESS_MODEL_ID, &dcModelId));
    NAPI_CALL(env, napi_create_uint32(env, ModelIdType::PHYSICAL_MACHINE_DETECTION_MODEL_ID, &pmdModelId));
    NAPI_CALL(env, napi_create_uint32(env, ModelIdType::SECURITY_AUDIT_MODEL_ID, &saModeltId));
    NAPI_CALL(env, napi_set_named_property(env, modelIdType, "ROOT_SCAN_MODEL_ID", rsModelId));
    NAPI_CALL(env, napi_set_named_property(env, modelIdType, "DEVICE_COMPLETENESS_MODEL_ID", dcModelId));
    NAPI_CALL(env, napi_set_named_property(env, modelIdType, "PHYSICAL_MACHINE_DETECTION_MODEL_ID", pmdModelId));
    NAPI_CALL(env, napi_set_named_property(env, modelIdType, "SECURITY_AUDIT_MODEL_ID", saModeltId));
    return modelIdType;
}

static napi_value NapiSetModelState(napi_env env, napi_callback_info info)
{
    size_t argc = NAPI_SET_MODEL_STATE_ARGS_MAX_CNT;
    napi_value argv[NAPI_SET_MODEL_STATE_ARGS_MAX_CNT] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != NAPI_SET_MODEL_STATE_ARGS_MAX_CNT) {
        SGLOGE("set model state arguments count is not expected");
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM));
        return nullptr;
    }

    size_t index = 0;
    uint32_t modelId = 0;
    if (ParseUint32(env, argv[index], modelId) == nullptr) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM));
        return nullptr;
    }

    if (modelId != ModelIdType::SECURITY_AUDIT_MODEL_ID) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM,
            "Parameter error, only supported SECURITY_AUDIT_MODEL_ID"));
        return nullptr;
    }

    index++;
    bool enable = false;
    if (ParseBool(env, argv[index], enable) == nullptr) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM));
        return nullptr;
    }

    int32_t code = SecurityGuardSdkAdaptor::SetModelState(modelId, enable);
    if (code != SUCCESS) {
        SGLOGE("set model state error, code=%{public}d", code);
    }
    return NapiCreateInt32(env, ConvertToJsErrCode(code));
}

EXTERN_C_START
static napi_value SecurityGuardNapiRegister(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("EventIdType", EventIdTypeConstructor(env)),
        DECLARE_NAPI_PROPERTY("ModelIdType", ModelIdTypeConstructor(env)),
        DECLARE_NAPI_FUNCTION("reportSecurityInfo", NapiReportSecurityInfo),
        DECLARE_NAPI_FUNCTION("requestSecurityEventInfo", NapiRequestSecurityEventInfo),
        DECLARE_NAPI_FUNCTION("requestSecurityModelResult", NapiRequestSecurityModelResult),
        DECLARE_NAPI_FUNCTION("setModelState", NapiSetModelState),
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