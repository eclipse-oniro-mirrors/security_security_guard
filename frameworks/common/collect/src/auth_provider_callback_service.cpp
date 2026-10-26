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

// 批次二（待评估）: OnClientStatusChanged 持 notifyMutex_ 调用外部 callback 是反模式（持锁回调可能死锁）。
// 但 notifyMutex_ 不能简单移除——它保护 callback_ 捕获资源（如 NAPI napi_ref）的生命周期：
// ClearCallBack 必须等 OnClientStatusChanged 执行完才能销毁资源，否则 OnClientStatusChanged 持有的
// callback 副本会引用已销毁的资源 → UAF。完整修复需重构为 shared_ptr<callback wrapper> 引用计数方案，
// 让 callback 执行移到锁外同时保证资源安全。当前保持现状，添加注释说明语义约束。
int32_t AuthProviderCallbackService::OnClientStatusChanged(const std::vector<AuthClientInfo> &clientsInfo)
{
    // notifyMutex_ 串行化回调执行 + 保护 callback_ 捕获资源的生命周期（防止 ClearCallBack 并发销毁资源）
    std::lock_guard<ffrt::mutex> execLock(mutexes_->notifyMutex_);
    std::function<void(const std::vector<AuthClientInfo> &clientsInfo)> callback;
    {
        // callbackMutex_ 仅保护 callback_ 变量的读写，临界区极短
        std::lock_guard<ffrt::mutex> slotLock(mutexes_->callbackMutex_);
        callback = callback_;
    }
    if (callback == nullptr) {
        SGLOGE("callback is null");
        return FAILED;
    }
    SGLOGD("OnClientStatusChanged size=%{public}zu", clientsInfo.size());
    callback(clientsInfo);  // 持 notifyMutex_ 执行：保证 ClearCallBack 等待回调完成后再销毁资源
    return SUCCESS;
}
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
