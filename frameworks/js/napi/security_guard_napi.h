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

#ifndef SECURITY_GUARD_NAPI_H
#define SECURITY_GUARD_NAPI_H

#include <thread>
#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "security_event.h"
#include "security_guard_define.h"
#include "event_define.h"

struct RequestSecurityEventInfoContext {
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    uint32_t status = 0;
    pid_t threadId;
    std::string devId;
    std::string info;
    std::vector<int64_t> eventIds;
    std::string beginTime;
    std::string endTime;
    std::string conditions;
    std::string errMsg;
    napi_ref dataCallback = nullptr;
    napi_ref endCallback = nullptr;
    napi_ref errorCallback = nullptr;
};

struct RequestSecurityModelResultContext {
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    napi_deferred deferred;
    napi_async_work asyncWork;
    std::string deviceId;
    std::string param;
    uint32_t modelId;
    OHOS::Security::SecurityGuard::SecurityModel result;
    int32_t ret;
};

struct ReportSecurityEventInfoContext {
    int64_t eventId;
    std::string version;
    std::string content;
};


struct NotifyCollectorContext {
    OHOS::Security::SecurityCollector::Event event;
    int64_t duration;
};

struct NapiSecurityEventRuler {
    int64_t eventId;
    std::string beginTime;
    std::string endTime;
    std::string param;
};

struct NapiSecurityEvent {
    int64_t eventId;
    std::string version;
    std::string content;
    std::string timestamp;
};
struct SubscribeEventInfo {
    int64_t eventId;
};

struct ModelRule {
    std::string modelName;
    std::string param;
};

struct NapiSecurityPolicyFileInfo {
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    napi_deferred deferred;
    napi_async_work asyncWork;
    std::string fileName;
    int32_t fd;
    int32_t ret;
};

using CALLBACK_FUNC = std::function<void(const napi_env, const napi_ref, pid_t threadId,
    const std::vector<OHOS::Security::SecurityCollector::SecurityEvent> &napiEvents)>;
using RELEASE_FUNC = std::function<void(pid_t threadId)>;

struct QuerySecurityEventContext {
    QuerySecurityEventContext() = default;
    explicit QuerySecurityEventContext(QuerySecurityEventContext *context)
        : env(context->env), ref(context->ref),
          callback(context->callback),
          release(context->release),
          threadId(context->threadId),
          events(context->events) {};

    napi_env env = nullptr;
    napi_ref ref = nullptr;
    CALLBACK_FUNC callback;
    RELEASE_FUNC release;
    pid_t threadId;
    std::vector<OHOS::Security::SecurityCollector::SecurityEvent> events;
};

enum EventIdType : int64_t {
    PRINTER_EVENT_ID = 1011015004
};

enum ModelIdType : uint32_t {
    ROOT_SCAN_MODEL_ID = 3001000000,
    DEVICE_COMPLETENESS_MODEL_ID = 3001000001,
    PHYSICAL_MACHINE_DETECTION_MODEL_ID = 3001000002,
    SECURITY_AUDIT_MODEL_ID = 3001000003,
    SECURITY_RISK_FACTOR_MODEL_ID = 3001000009,
    WLAN_RISK_DETECTION_MODEL_ID = 3001000011,
};

enum JsErrCode : int32_t {
    JS_ERR_SUCCESS = 0,
    JS_ERR_NO_PERMISSION = 201,
    JS_ERR_NO_SYSTEMCALL = 202,
    JS_ERR_BAD_PARAM = 401,
    JS_ERR_API_SUPPORT_ERROR = 801,
    JS_ERR_SYS_ERR = 21200001,
    JS_ERR_AUTH_PROVIDER_INTERNAL = 27000001,
    JS_ERR_AUTH_PROVIDER_EXCEED_PROCESS = 27000002,
    JS_ERR_AUTH_PROVIDER_EXCEED_GLOBAL = 27000003,
    JS_ERR_AUTH_REQUEST_EXCEED_LIMIT = 27000004,
};

// 错误码转换（供 napi_block_framework.cpp 共享使用）
int32_t ConvertToJsErrCode(int32_t code);
std::string ConvertToJsErrMsg(int32_t code);
napi_value GenerateBusinessError(napi_env env, int32_t code);
napi_value GenerateBusinessError(napi_env env, int32_t code, const std::string &msg);

class SubscriberPtr;
struct CommonAsyncContext {
    CommonAsyncContext() {};
    explicit CommonAsyncContext(napi_env napiEnv, std::thread::id thId,
        bool throwAble = false) : env(napiEnv), threadId(thId), throwErr(throwAble) {};
    virtual ~CommonAsyncContext()
    {
        if (env == nullptr) {
            return;
        }
        if (callbackRef != nullptr) {
            napi_delete_reference(env, callbackRef);
            callbackRef = nullptr;
        }
        if (work != nullptr) {
            napi_delete_async_work(env, work);
            work = nullptr;
        }
    };
    napi_env env = nullptr;
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callbackRef = nullptr;
    napi_status status = napi_ok;
    int32_t errCode = 0;
    std::string errMsg;
    std::thread::id threadId;
    bool throwErr = false;
};
struct SubscribeCBInfo : public CommonAsyncContext {
    explicit SubscribeCBInfo(napi_env napiEnv,
        std::thread::id thId) : CommonAsyncContext(napiEnv, thId) {};
    OHOS::Security::SecurityCollector::Event events {};
    std::shared_ptr<SubscriberPtr> subscriber = nullptr;
};

struct UnsubscribeCBInfo : public CommonAsyncContext {
    explicit UnsubscribeCBInfo(napi_env napiEnv,
        std::thread::id thId) : CommonAsyncContext(napiEnv, thId){};
    OHOS::Security::SecurityCollector::Event events {};
    std::vector<std::shared_ptr<SubscriberPtr>> subscribers;
};

struct SubscriberOAWorker : public CommonAsyncContext {
    NapiSecurityEvent event {};
    napi_ref ref = nullptr;
    SubscriberPtr *subscriber = nullptr;
};
#endif // SECURITY_GUARD_NAPI_H