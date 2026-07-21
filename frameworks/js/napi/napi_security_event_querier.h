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

#ifndef NAPI_SECURITY_EVENT_QUERIER_H
#define NAPI_SECURITY_EVENT_QUERIER_H

#include <functional>
#include <string>
#include <vector>

#include "uv.h"

#include "security_guard_napi.h"
#include "security_event_query_callback.h"

namespace OHOS::Security::SecurityGuard {
constexpr char ON_QUERY_ATTR[] = "onQuery";
constexpr char ON_COMPLETE_ATTR[] = "onComplete";
constexpr char ON_ERROR_ATTR[] = "onError";
using ON_COMPLETE_FUNC = std::function<void(const napi_env, const napi_ref)>;
class NapiSecurityEventQuerier : public SecurityEventQueryCallback {
public:
    NapiSecurityEventQuerier(QuerySecurityEventContext *context, ON_COMPLETE_FUNC handler);
    ~NapiSecurityEventQuerier() override;
    static napi_value NapiGetNamedProperty(const napi_env env, const napi_value &object, const std::string &name);
    static napi_value NapiCreateString(const napi_env env, const std::string &value);
    static napi_value NapiCreateInt64(const napi_env env, int64_t value);
    static napi_value ConvertEventsToJsArray(const napi_env env,
    const std::vector<SecurityCollector::SecurityEvent> &napiEvents);
    void RunCallback(QuerySecurityEventContext *context, CALLBACK_FUNC callback, RELEASE_FUNC release);
    void OnQuery(const std::vector<SecurityCollector::SecurityEvent> &events) override;
    void OnComplete() override;
    void OnError(const std::string &message) override;

private:
    QuerySecurityEventContext* callbackContext_;
    ON_COMPLETE_FUNC onCompleteHandler_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // NAPI_SECURITY_EVENT_QUERIER_H
