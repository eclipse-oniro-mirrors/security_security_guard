/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "napi_block_framework.h"

#include <memory>
#include <vector>

#include "security_guard_napi.h"
#include "ffrt.h"
#include "security_guard_log.h"
#include "security_guard_sdk_adaptor.h"

using namespace OHOS::Security::SecurityGuard;

// 未开启 SECURITY_GUARD_AUTH_EVENT_ENABLE 时, createAuthProvider/destroyAuthProvider 返回 801
#ifndef SECURITY_GUARD_AUTH_EVENT_ENABLE
napi_value OHOS::Security::SecurityGuard::NapiCreateAuthProvider(napi_env env, napi_callback_info info)
{
    napi_throw(env, GenerateBusinessError(env, API_SUPPORT_ERROR, "API is not supported"));
    return nullptr;
}

napi_value OHOS::Security::SecurityGuard::NapiDestroyAuthProvider(napi_env env, napi_callback_info info)
{
    napi_throw(env, GenerateBusinessError(env, API_SUPPORT_ERROR, "API is not supported"));
    return nullptr;
}
#else

#include "security_guard_define.h"

namespace {
constexpr int NAPI_CREATE_PROVIDER_ARGS_CNT = 2;
constexpr int NAPI_DESTROY_PROVIDER_ARGS_CNT = 1;
constexpr int NAPI_REQUEST_AUTH_RESULT_ARGS_CNT = 1;
constexpr int SERVICE_ID_MAX_LEN = 256;
constexpr int NAPI_CONTENT_MAX_LEN = 4096;
constexpr int NAPI_VERSION_MAX_LEN = 64;
constexpr const char* PROVIDER_CALLBACK_NAME = "onClientStatusChanged";

napi_value NapiCreateInt32(napi_env env, int32_t value)
{
    napi_value result = nullptr;
    napi_status status = napi_create_int32(env, value, &result);
    if (status != napi_ok || result == nullptr) {
        SGLOGE("failed to create napi value of int32 type.");
    }
    return result;
}

napi_value NapiCreateInt64(napi_env env, int64_t value)
{
    napi_value result = nullptr;
    napi_status status = napi_create_int64(env, value, &result);
    if (status != napi_ok || result == nullptr) {
        SGLOGE("failed to create napi value of int64 type.");
    }
    return result;
}

napi_value NapiCreateString(napi_env env, const std::string &value)
{
    napi_value result = nullptr;
    napi_status status = napi_create_string_utf8(env, value.c_str(), NAPI_AUTO_LENGTH, &result);
    if (status != napi_ok || result == nullptr) {
        SGLOGE("failed to create napi value of string type.");
    }
    return result;
}

napi_value NapiCreateObject(napi_env env)
{
    napi_value result = nullptr;
    napi_status status = napi_create_object(env, &result);
    if (status != napi_ok || result == nullptr) {
        SGLOGE("failed to create napi value of object type.");
    }
    return result;
}

napi_value WrapVoidToJS(napi_env env)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

// Provider 接口错误码归一化: 不在 g_errorStringMap 中的统一归入 AUTH_PROVIDER_INTERNAL_ERROR
int32_t NormalizeProviderError(int32_t code)
{
    int32_t jsErrCode = ConvertToJsErrCode(code);
    if (jsErrCode == JS_ERR_SYS_ERR) {
        return AUTH_PROVIDER_INTERNAL_ERROR;
    }
    return code;
}

bool ParseString(napi_env env, napi_value object, const std::string &key, std::string &value, uint32_t maxLen)
{
    bool hasProperty = false;
    napi_has_named_property(env, object, key.c_str(), &hasProperty);
    if (!hasProperty) {
        SGLOGE("no such param %{public}s", key.c_str());
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "no such param " + key));
        return false;
    }
    napi_value result = nullptr;
    napi_get_named_property(env, object, key.c_str(), &result);
    if (result == nullptr) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "get key failed."));
        return false;
    }
    napi_valuetype type;
    napi_typeof(env, result, &type);
    if (type != napi_string) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "type of param is not string."));
        return false;
    }
    size_t size = 0;
    napi_get_value_string_utf8(env, result, nullptr, 0, &size);
    if (size >= maxLen) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "param is too long"));
        return false;
    }
    std::vector<char> buf(size + 1, '\0');
    napi_get_value_string_utf8(env, result, buf.data(), size + 1, &size);
    value = std::string{buf.data()};
    return true;
}

bool ParseInt64(napi_env env, napi_value object, const std::string &key, int64_t &value)
{
    bool hasProperty = false;
    napi_has_named_property(env, object, key.c_str(), &hasProperty);
    if (!hasProperty) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "no such param " + key));
        return false;
    }
    napi_value result = nullptr;
    napi_get_named_property(env, object, key.c_str(), &result);
    if (result == nullptr) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "get key failed."));
        return false;
    }
    napi_valuetype type;
    napi_typeof(env, result, &type);
    if (type != napi_number) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "type of param is not number."));
        return false;
    }
    napi_get_value_int64(env, result, &value);
    return true;
}

bool ParseInt32(napi_env env, napi_value object, const std::string &key, int32_t &value)
{
    bool hasProperty = false;
    napi_has_named_property(env, object, key.c_str(), &hasProperty);
    if (!hasProperty) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "no such param " + key));
        return false;
    }
    napi_value result = nullptr;
    napi_get_named_property(env, object, key.c_str(), &result);
    if (result == nullptr) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "get key failed."));
        return false;
    }
    napi_valuetype type;
    napi_typeof(env, result, &type);
    if (type != napi_number) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "type of param is not number."));
        return false;
    }
    napi_get_value_int32(env, result, &value);
    return true;
}

bool ParseOneClientStatus(napi_env env, napi_value item, AuthClientStatus &status)
{
    std::string clientId;
    if (!ParseString(env, item, "clientId", clientId, SERVICE_ID_MAX_LEN)) {
        return false;
    }
    bool hasDegrader = false;
    napi_has_named_property(env, item, "isDegraded", &hasDegrader);
    if (hasDegrader) {
        napi_value degVal = nullptr;
        napi_get_named_property(env, item, "isDegraded", &degVal);
        if (degVal != nullptr) {
            bool isDegrader = false;
            napi_get_value_bool(env, degVal, &isDegrader);
            status.SetDegraded(isDegrader);
        }
    }
    status.SetClientId(clientId);
    return true;
}

void ParseClientStatusArray(napi_env env, napi_value statusArr, AuthEventInfo &info)
{
    bool isArray = false;
    napi_is_array(env, statusArr, &isArray);
    if (!isArray) {
        return;
    }
    std::vector<AuthClientStatus> statusList;
    uint32_t length = 0;
    napi_get_array_length(env, statusArr, &length);
    for (uint32_t i = 0; i < length; ++i) {
        napi_value item = nullptr;
        napi_get_element(env, statusArr, i, &item);
        if (item == nullptr) {
            continue;
        }
        AuthClientStatus status;
        if (ParseOneClientStatus(env, item, status)) {
            statusList.push_back(status);
        }
    }
    info.SetClientStatus(statusList);
}

bool ParseAuthEventInfo(napi_env env, napi_value jsObj, AuthEventInfo &info)
{
    napi_valuetype type = napi_undefined;
    napi_typeof(env, jsObj, &type);
    if (type != napi_object) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "type of param eventInfo is not object"));
        return false;
    }
    int64_t eventId = 0;
    if (!ParseInt64(env, jsObj, "eventId", eventId)) {
        return false;
    }
    info.SetEventId(eventId);
    std::string version;
    if (!ParseString(env, jsObj, "version", version, NAPI_VERSION_MAX_LEN)) {
        return false;
    }
    info.SetVersion(version);
    std::string content;
    if (!ParseString(env, jsObj, "content", content, NAPI_CONTENT_MAX_LEN)) {
        return false;
    }
    info.SetContent(content);
    bool hasClientStatus = false;
    napi_has_named_property(env, jsObj, "clientStatus", &hasClientStatus);
    if (hasClientStatus) {
        napi_value statusArr = nullptr;
        napi_get_named_property(env, jsObj, "clientStatus", &statusArr);
        if (statusArr != nullptr) {
            ParseClientStatusArray(env, statusArr, info);
        }
    }
    return true;
}

napi_value WrapAuthResult(napi_env env, const AuthResult &result)
{
    napi_value jsResult = NapiCreateObject(env);
    napi_value strategy = NapiCreateInt32(env, static_cast<int32_t>(result.GetMergedAuthStrategy()));
    napi_set_named_property(env, jsResult, "mergedAuthStrategy", strategy);

    auto clientResults = result.GetClientAuthResult();
    napi_value jsArray = nullptr;
    napi_create_array_with_length(env, clientResults.size(), &jsArray);
    for (size_t i = 0; i < clientResults.size(); ++i) {
        napi_value jsItem = NapiCreateObject(env);
        napi_value clientId = NapiCreateString(env, clientResults[i].GetClientId());
        napi_value authStrategy = NapiCreateInt32(env, static_cast<int32_t>(clientResults[i].GetAuthStrategy()));
        napi_set_named_property(env, jsItem, "clientId", clientId);
        napi_set_named_property(env, jsItem, "authStrategy", authStrategy);
        napi_set_element(env, jsArray, i, jsItem);
    }
    napi_set_named_property(env, jsResult, "clientAuthResult", jsArray);
    return jsResult;
}

void OnClientStatusChangedCallback(napi_env env, napi_ref callbackRef,
    const std::vector<AuthClientInfo> &clientsInfo)
{
    if (env == nullptr || callbackRef == nullptr) {
        return;
    }
    napi_value callbackFunc = nullptr;
    napi_get_reference_value(env, callbackRef, &callbackFunc);
    if (callbackFunc == nullptr) {
        SGLOGE("callback function is null");
        return;
    }
    napi_value jsArray = nullptr;
    napi_create_array_with_length(env, clientsInfo.size(), &jsArray);
    for (size_t i = 0; i < clientsInfo.size(); ++i) {
        napi_value jsItem = NapiCreateObject(env);
        napi_value clientId = NapiCreateString(env, clientsInfo[i].GetClientId());
        napi_value bundleName = NapiCreateString(env, clientsInfo[i].GetBundleName());
        napi_value strategy = NapiCreateInt32(env, static_cast<int32_t>(clientsInfo[i].GetDefaultTimeoutStrategy()));
        napi_value timeouts = NapiCreateInt32(env, clientsInfo[i].GetDefaultTimeoutMs());
        napi_set_named_property(env, jsItem, "clientId", clientId);
        napi_set_named_property(env, jsItem, "bundleName", bundleName);
        napi_set_named_property(env, jsItem, "defaultTimeoutStrategy", strategy);
        napi_set_named_property(env, jsItem, "defaultTimeoutMs", timeouts);
        auto events = clientsInfo[i].GetSubscribedEvents();
        napi_value jsEvents = nullptr;
        napi_create_array_with_length(env, events.size(), &jsEvents);
        for (size_t j = 0; j < events.size(); ++j) {
            napi_set_element(env, jsEvents, j, NapiCreateInt64(env, events[j]));
        }
        napi_set_named_property(env, jsItem, "subscribedEvents", jsEvents);
        napi_set_element(env, jsArray, i, jsItem);
    }
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);
    napi_value returnVal = nullptr;
    napi_call_function(env, undefined, callbackFunc, 1, &jsArray, &returnVal);
}
}

namespace OHOS::Security::SecurityGuard {

// SA 聚合完成后回调 → kit 收到 AuthResult → resolve Promise<AuthResult>
void RequestAuthResultExecute(napi_env env, void *data)
{
    auto *context = static_cast<RequestAuthResultContext *>(data);
    if (context == nullptr || context->provider == nullptr) {
        return;
    }
    // 回调 stub 已在主线程创建，此处直接调 SA
    context->ret = SecurityGuardSdkAdaptor::RequestAuthResult(context->provider, context->eventInfo,
        [context](const AuthResult &authResult) {
            context->result = authResult;
        });
    if (context->ret != SUCCESS) {
        SGLOGE("RequestAuthResult rejected, ret=%{public}d", context->ret);
    }
}

void RequestAuthResultComplete(napi_env env, napi_status status, void *data)
{
    auto *context = static_cast<RequestAuthResultContext *>(data);
    if (context == nullptr) {
        return;
    }
    if (context->ret == SUCCESS) {
        // 请求被接受，SA 异步聚合完成后经回调 resolve Promise
        napi_value jsResult = WrapAuthResult(env, context->result);
        napi_resolve_deferred(env, context->deferred, jsResult);
    } else {
        napi_value error = GenerateBusinessError(env, NormalizeProviderError(context->ret),
            "RequestAuthResult rejected");
        napi_reject_deferred(env, context->deferred, error);
    }
    napi_delete_async_work(env, context->asyncWork);
    delete context;
}

napi_value NapiRequestAuthResult(napi_env env, napi_callback_info info)
{
    size_t argc = NAPI_REQUEST_AUTH_RESULT_ARGS_CNT;
    napi_value argv[NAPI_REQUEST_AUTH_RESULT_ARGS_CNT] = {nullptr};
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != NAPI_REQUEST_AUTH_RESULT_ARGS_CNT) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "arguments count is not expected"));
        return nullptr;
    }
    NapiAuthProvider *provider = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&provider));
    if (provider == nullptr || provider->provider == nullptr) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "provider is null or invalid"));
        return nullptr;
    }
    AuthEventInfo eventInfo;
    if (!ParseAuthEventInfo(env, argv[0], eventInfo)) {
        return nullptr;
    }
    auto *context = new (std::nothrow) RequestAuthResultContext();
    if (context == nullptr) {
        napi_throw(env, GenerateBusinessError(env, AUTH_PROVIDER_INTERNAL_ERROR, "no memory"));
        return nullptr;
    }
    context->env = env;
    context->eventInfo = eventInfo;
    context->provider = provider->provider;
    // 主线程创建回调 stub（避免 SA 无订阅时立即回调导致 Execute 未完成就触发）
    context->resultCallback = new (std::nothrow) AuthResultCallbackService();
    if (context->resultCallback == nullptr) {
        delete context;
        napi_throw(env, GenerateBusinessError(env, AUTH_PROVIDER_INTERNAL_ERROR, "callback service alloc fail"));
        return nullptr;
    }
    context->resultCallback->RegistCallBack(
        [context](const AuthResult &authResult) {
            context->result = authResult;
        });

    napi_value promise = nullptr;
    if (napi_create_promise(env, &context->deferred, &promise) != napi_ok) {
        delete context;
        napi_throw(env, GenerateBusinessError(env, AUTH_PROVIDER_INTERNAL_ERROR, "napi_create_promise failed"));
        return nullptr;
    }
    napi_value resourceName = NapiCreateString(env, "NapiRequestAuthResult");
    if (napi_create_async_work(env, nullptr, resourceName, RequestAuthResultExecute,
        RequestAuthResultComplete, static_cast<void *>(context), &context->asyncWork) != napi_ok) {
        delete context;
        napi_throw(env, GenerateBusinessError(env, AUTH_PROVIDER_INTERNAL_ERROR, "napi_create_async_work failed"));
        return nullptr;
    }
    if (napi_queue_async_work(env, context->asyncWork) != napi_ok) {
        napi_delete_async_work(env, context->asyncWork);
        delete context;
        napi_throw(env, GenerateBusinessError(env, AUTH_PROVIDER_INTERNAL_ERROR, "napi_queue_async_work failed"));
        return nullptr;
    }
    return promise;
}

void NapiAuthProviderFinalize(napi_env env, void *data, void *hint)
{
    auto *provider = static_cast<NapiAuthProvider *>(data);
    if (provider == nullptr) {
        return;
    }
    if (provider->provider != nullptr) {
        provider->provider->DeleteProvider();
        provider->provider = nullptr;
    }
    if (provider->callbackRef != nullptr) {
        napi_delete_reference(env, provider->callbackRef);
        provider->callbackRef = nullptr;
    }
    delete provider;
}

bool ParseServiceId(napi_env env, napi_value jsVal, std::string &serviceId)
{
    napi_valuetype type = napi_undefined;
    napi_typeof(env, jsVal, &type);
    if (type != napi_string) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "serviceId is not string"));
        return false;
    }
    size_t size = 0;
    napi_get_value_string_utf8(env, jsVal, nullptr, 0, &size);
    if (size >= SERVICE_ID_MAX_LEN) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "serviceId is too long"));
        return false;
    }
    std::vector<char> buf(size + 1, '\0');
    napi_get_value_string_utf8(env, jsVal, buf.data(), size + 1, &size);
    serviceId = std::string{buf.data()};
    return true;
}

napi_value NapiCreateAuthProvider(napi_env env, napi_callback_info info)
{
    size_t argc = NAPI_CREATE_PROVIDER_ARGS_CNT;
    napi_value argv[NAPI_CREATE_PROVIDER_ARGS_CNT] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc != NAPI_CREATE_PROVIDER_ARGS_CNT) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "arguments count is not expected"));
        return nullptr;
    }
    napi_valuetype callbackType;
    napi_typeof(env, argv[0], &callbackType);
    if (callbackType != napi_object) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "callback is not object"));
        return nullptr;
    }
    std::string serviceId;
    if (!ParseServiceId(env, argv[1], serviceId)) {
        return nullptr;
    }
    napi_value callbackMethod = nullptr;
    napi_get_named_property(env, argv[0], PROVIDER_CALLBACK_NAME, &callbackMethod);
    if (callbackMethod == nullptr) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "onClientStatusChanged not found"));
        return nullptr;
    }
    napi_valuetype methodType;
    napi_typeof(env, callbackMethod, &methodType);
    if (methodType != napi_function) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "onClientStatusChanged is not function"));
        return nullptr;
    }
    auto *nativeProvider = new (std::nothrow) NapiAuthProvider();
    if (nativeProvider == nullptr) {
        napi_throw(env, GenerateBusinessError(env, AUTH_PROVIDER_INTERNAL_ERROR, "no memory"));
        return nullptr;
    }
    nativeProvider->env = env;
    napi_create_reference(env, argv[0], 1, &nativeProvider->callbackRef);
    AuthProviderCallback callback = [env, ref = nativeProvider->callbackRef](
        const std::vector<AuthClientInfo> &clientsInfo) {
        OnClientStatusChangedCallback(env, ref, clientsInfo);
    };
    std::shared_ptr<AuthProviderSubscribeClient> provider = nullptr;
    int32_t ret = SecurityGuardSdkAdaptor::CreateProvider(callback, serviceId, provider);
    if (ret != SUCCESS || provider == nullptr) {
        if (nativeProvider->callbackRef != nullptr) {
            napi_delete_reference(env, nativeProvider->callbackRef);
        }
        delete nativeProvider;
        napi_throw(env, GenerateBusinessError(env, NormalizeProviderError(ret), "CreateProvider failed"));
        return nullptr;
    }
    nativeProvider->provider = provider;
    napi_value jsObj = NapiCreateObject(env);
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("requestAuthResult", NapiRequestAuthResult),
    };
    napi_define_properties(env, jsObj, sizeof(desc) / sizeof(desc[0]), desc);
    napi_wrap(env, jsObj, nativeProvider, NapiAuthProviderFinalize, nullptr, nullptr);
    SGLOGI("createAuthProvider success, serviceId=%{public}s", serviceId.c_str());
    return jsObj;
}

napi_value NapiDestroyAuthProvider(napi_env env, napi_callback_info info)
{
    size_t argc = NAPI_DESTROY_PROVIDER_ARGS_CNT;
    napi_value argv[NAPI_DESTROY_PROVIDER_ARGS_CNT] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc != NAPI_DESTROY_PROVIDER_ARGS_CNT) {
        napi_throw(env, GenerateBusinessError(env, BAD_PARAM, "arguments count is not expected"));
        return nullptr;
    }
    NapiAuthProvider *nativeProvider = nullptr;
    napi_unwrap(env, argv[0], reinterpret_cast<void **>(&nativeProvider));
    if (nativeProvider == nullptr) {
        return WrapVoidToJS(env);
    }
    if (nativeProvider->provider != nullptr) {
        nativeProvider->provider->DeleteProvider();
        nativeProvider->provider = nullptr;
    }
    if (nativeProvider->callbackRef != nullptr) {
        napi_delete_reference(env, nativeProvider->callbackRef);
        nativeProvider->callbackRef = nullptr;
    }
    // 不取回指针，不手动 delete，交给 NapiAuthProviderFinalize 在 GC 时释放
    napi_remove_wrap(env, argv[0], nullptr);
    SGLOGI("destroyAuthProvider success");
    return WrapVoidToJS(env);
}
} // namespace OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
