/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "napi_security_event_querier.h"

#include <unistd.h>

#include "security_guard_define.h"
#include "security_guard_log.h"
#include "napi_request_data_manager.h"

namespace OHOS::Security::SecurityGuard {
NapiSecurityEventQuerier::NapiSecurityEventQuerier(QuerySecurityEventContext *context, ON_COMPLETE_FUNC handler)
    : callbackContext_(context), onCompleteHandler_(handler) {};
NapiSecurityEventQuerier::~NapiSecurityEventQuerier()
{
    if (callbackContext_ != nullptr) {
        napi_env env = callbackContext_->env;
        napi_ref ref = callbackContext_->ref;
        pid_t threadId = callbackContext_->threadId;
        delete callbackContext_;
        callbackContext_ = nullptr;
        if (env != nullptr && threadId == getproctid()) {
            napi_delete_reference(env, ref);
        }
    }
};

napi_value NapiSecurityEventQuerier::NapiGetNamedProperty(const napi_env env, const napi_value &object,
    const std::string &name)
{
    napi_value result = nullptr;
    napi_status status = napi_get_named_property(env, object, name.c_str(), &result);
    if (status != napi_ok || result == nullptr) {
        SGLOGE("failed to parse property named %{public}s from JS object.", name.c_str());
    }
    return result;
}

napi_value NapiSecurityEventQuerier::NapiCreateString(const napi_env env, const std::string &value)
{
    napi_value result = nullptr;
    napi_status status = napi_create_string_utf8(env, value.c_str(), NAPI_AUTO_LENGTH, &result);
    SGLOGD("create napi value of string type, value is %{public}s.", value.c_str());
    if (status != napi_ok || result == nullptr) {
        SGLOGE("failed to create napi value of string type.");
    }
    return result;
}

napi_value NapiSecurityEventQuerier::NapiCreateInt64(const napi_env env, int64_t value)
{
    napi_value result = nullptr;
    napi_status status = napi_create_int64(env, value, &result);
    SGLOGI("create napi value of int64 type, value is %{public}" PRId64, value);
    if (status != napi_ok || result == nullptr) {
        SGLOGE("failed to create napi value of int64 type.");
    }
    return result;
}

void NapiSecurityEventQuerier::RunCallback(QuerySecurityEventContext *context, CALLBACK_FUNC callback,
    RELEASE_FUNC release)
{
    if (context == nullptr) {
        SGLOGE("context is nullptr");
        return;
    }
    auto tmpContext = std::make_shared<QuerySecurityEventContext>(context);
    auto task = [tmpContext, callback, release]() {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(tmpContext->env, &scope);
        if (scope == nullptr) {
            return;
        }
        if (callback != nullptr) {
            SGLOGD("Begin execute callback.");
            callback(tmpContext->env, tmpContext->ref, tmpContext->threadId, tmpContext->events);
        }
        napi_close_handle_scope(tmpContext->env, scope);
        if (release != nullptr) {
            release(tmpContext->threadId);
        }
    };
    napi_send_event(tmpContext->env, task, napi_eprio_high, "NapiSecurityEventQuerier::RunCallback");
}

void NapiSecurityEventQuerier::OnQuery(const std::vector<SecurityCollector::SecurityEvent> &events)
{
    SGLOGD("NAPI OnQuery.");
    callbackContext_->events = events;

    RunCallback(callbackContext_,
        [this] (const napi_env env, const napi_ref ref, pid_t threadId,
            const std::vector<SecurityCollector::SecurityEvent> &napiEvents) {
            SGLOGD("NAPI OnQuery Callback.");
            if (threadId != getproctid() || !NapiRequestDataManager::GetInstance().GetDataCallback(env)) {
                return;
            }
            napi_value eventJsArray = nullptr;
            napi_create_array_with_length(env, napiEvents.size(), &eventJsArray);
            auto len = napiEvents.size();
            for (size_t i = 0; i < len; i++) {
                napi_value item = nullptr;
                napi_status status = napi_create_object(env, &item);
                if (status != napi_ok) {
                    SGLOGE("napi_create_object failed, %{public}d", status);
                    return;
                }
                napi_value eventId = NapiCreateInt64(env, napiEvents[i].GetEventId());
                napi_value version = NapiCreateString(env, napiEvents[i].GetVersion().c_str());
                napi_value content = NapiCreateString(env, napiEvents[i].GetContent().c_str());
                napi_value timestamp = NapiCreateString(env, napiEvents[i].GetTimestamp().c_str());
                napi_set_named_property(env, item, "eventId", eventId);
                napi_set_named_property(env, item, "version", version);
                napi_set_named_property(env, item, "content", content);
                napi_set_named_property(env, item, "timestamp", timestamp);
                status = napi_set_element(env, eventJsArray, i, item);
                if (status != napi_ok) {
                    SGLOGE("napi_set_element failed, %{public}d", status);
                    return;
                }
            }
            napi_value argv[1] = {eventJsArray};
            napi_value querier = nullptr;
            napi_get_reference_value(env, ref, &querier);
            napi_value onQuery = NapiGetNamedProperty(env, querier, ON_QUERY_ATTR);
            napi_value ret = nullptr;
            SGLOGD("NAPI begin call OnQuery.");
            napi_status res = napi_call_function(env, querier, onQuery, 1, argv, &ret);
            if (res != napi_ok) {
                SGLOGE("failed to call OnQuery JS function. %{public}d", res);
            }
            SGLOGD("NAPI OnQuery Callback END.");
        }, nullptr);
};

void NapiSecurityEventQuerier::OnComplete()
{
    RunCallback(callbackContext_, [] (const napi_env env, const napi_ref ref, pid_t threadId,
            const std::vector<SecurityCollector::SecurityEvent> &napiEvents) {
        SGLOGD("NAPI OnComplete Callback.");
        napi_value querier = nullptr;
        napi_get_reference_value(env, ref, &querier);
        napi_value onComplete = NapiGetNamedProperty(env, querier, ON_COMPLETE_ATTR);
        napi_value ret = nullptr;
        napi_status status = napi_call_function(env, querier, onComplete, 0, nullptr, &ret);
        if (status != napi_ok) {
            SGLOGE("failed to call onComplete JS function.");
        }
        SGLOGD("NAPI OnComplete Callback END.");
    }, [this] (pid_t threadId) {
        SGLOGD("NAPI OnComplete Release.");
        if (threadId != getproctid()) {
            return;
        }
        if (onCompleteHandler_ != nullptr && callbackContext_ != nullptr) {
            onCompleteHandler_(callbackContext_->env, callbackContext_->ref);
        }
        SGLOGD("NAPI OnComplete Release END.");
    });
};

void NapiSecurityEventQuerier::OnError(const std::string &message)
{
    RunCallback(callbackContext_, [message] (const napi_env env, const napi_ref ref, pid_t threadId,
            const std::vector<SecurityCollector::SecurityEvent> &napiEvents) {
        SGLOGD("NAPI OnError.");
        napi_value jsMessage = NapiCreateString(env, message);
        napi_value argv[1] = {jsMessage};
        napi_value querier = nullptr;
        napi_get_reference_value(env, ref, &querier);
        napi_value onQuery = NapiGetNamedProperty(env, querier, ON_ERROR_ATTR);
        napi_value ret = nullptr;
        napi_status status = napi_call_function(env, querier, onQuery, 1, argv, &ret);
        if (status != napi_ok) {
            SGLOGE("failed to call OnQuery JS function.");
        }
        SGLOGD("NAPI OnError END.");
    },  [this] (pid_t threadId) {
        if (threadId != getproctid()) {
            return;
        }
        if (onCompleteHandler_ != nullptr && callbackContext_ != nullptr) {
            onCompleteHandler_(callbackContext_->env, callbackContext_->ref);
        }
    });
};
} // OHOS::Security::SecurityGuard