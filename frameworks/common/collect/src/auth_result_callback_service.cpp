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

#include "auth_result_callback_service.h"

#include <memory>

#include "ffrt.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
namespace OHOS::Security::SecurityGuard {
struct AuthResultCallbackService::CallbackMutex {
    ffrt::mutex notifyMutex_;
    ffrt::mutex callbackMutex_;
};

AuthResultCallbackService::AuthResultCallbackService()
    : mutexes_(std::make_unique<CallbackMutex>()) {}

AuthResultCallbackService::~AuthResultCallbackService() = default;

void AuthResultCallbackService::RegistCallBack(std::function<void(const AuthResult &result)> callback)
{
    std::lock_guard<ffrt::mutex> lock(mutexes_->callbackMutex_);
    if (callback == nullptr) {
        return;
    }
    callback_ = callback;
}

void AuthResultCallbackService::ClearCallBack()
{
    std::lock_guard<ffrt::mutex> execLock(mutexes_->notifyMutex_);
    std::lock_guard<ffrt::mutex> slotLock(mutexes_->callbackMutex_);
    callback_ = nullptr;
}

// SA 聚合完成后回调 → 触发 std::function → C++ 调用方或 NAPI Promise resolve
int32_t AuthResultCallbackService::OnAuthResult(const AuthResult &result)
{
    std::lock_guard<ffrt::mutex> execLock(mutexes_->notifyMutex_);
    std::function<void(const AuthResult &result)> callback;
    {
        std::lock_guard<ffrt::mutex> slotLock(mutexes_->callbackMutex_);
        callback = callback_;
    }
    if (callback == nullptr) {
        SGLOGE("callback is null");
        return FAILED;
    }
    SGLOGD("OnAuthResult mergedStrategy=%{public}d", static_cast<int32_t>(result.GetMergedAuthStrategy()));
    callback(result);
    return SUCCESS;
}
} // namespace OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
