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

#include "auth_provider_callback_service.h"

#include <memory>

#include "ffrt.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
namespace OHOS::Security::SecurityGuard {
struct AuthProviderCallbackService::CallbackMutex {
    ffrt::mutex notifyMutex_;
    ffrt::mutex callbackMutex_;
};

AuthProviderCallbackService::AuthProviderCallbackService()
    : mutexes_(std::make_unique<CallbackMutex>()) {}

AuthProviderCallbackService::~AuthProviderCallbackService() = default;

void AuthProviderCallbackService::RegistCallBack(
    std::function<void(const std::vector<AuthClientInfo> &clientsInfo)> callback)
{
    std::lock_guard<ffrt::mutex> lock(mutexes_->callbackMutex_);
    if (callback == nullptr) {
        return;
    }
    callback_ = callback;
}

void AuthProviderCallbackService::ClearCallBack()
{
    std::lock_guard<ffrt::mutex> execLock(mutexes_->notifyMutex_);
    std::lock_guard<ffrt::mutex> slotLock(mutexes_->callbackMutex_);
    callback_ = nullptr;
}

int32_t AuthProviderCallbackService::OnClientsStatusChanged(const std::vector<AuthClientInfo> &clientsInfo)
{
    std::lock_guard<ffrt::mutex> execLock(mutexes_->notifyMutex_);
    std::function<void(const std::vector<AuthClientInfo> &clientsInfo)> callback;
    {
        std::lock_guard<ffrt::mutex> slotLock(mutexes_->callbackMutex_);
        callback = callback_;
    }
    if (callback == nullptr) {
        SGLOGE("callback is null");
        return FAILED;
    }
    SGLOGD("OnClientsStatusChanged size=%{public}zu", clientsInfo.size());
    callback(clientsInfo);
    return SUCCESS;
}
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
