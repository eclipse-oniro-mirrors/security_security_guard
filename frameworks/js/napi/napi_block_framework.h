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

#ifndef NAPI_BLOCK_FRAMEWORK_H
#define NAPI_BLOCK_FRAMEWORK_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "security_guard_define.h"

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
#include "auth_event_info.h"
#include "auth_provider_subscribe_client.h"
#include "auth_result.h"
#include "auth_result_callback_service.h"

namespace OHOS::Security::SecurityGuard {
struct NapiAuthProvider {
    std::shared_ptr<AuthProviderSubscribeClient> provider;
    napi_ref callbackRef = nullptr;
    napi_env env = nullptr;
};

// SA 聚合完成后经回调通知 kit → kit 收到 AuthResult → resolve Promise<AuthResult>
struct RequestAuthResultContext {
    napi_env env = nullptr;
    napi_deferred deferred = nullptr;
    napi_async_work asyncWork = nullptr;
    AuthEventInfo eventInfo;
    int32_t ret = 0;
    std::shared_ptr<AuthProviderSubscribeClient> provider;
    sptr<AuthResultCallbackService> resultCallback;
    AuthResult result;
};

napi_value NapiCreateAuthProvider(napi_env env, napi_callback_info info);
napi_value NapiDestroyAuthProvider(napi_env env, napi_callback_info info);
napi_value NapiRequestAuthResult(napi_env env, napi_callback_info info);
} // namespace OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE

#endif // NAPI_BLOCK_FRAMEWORK_H
