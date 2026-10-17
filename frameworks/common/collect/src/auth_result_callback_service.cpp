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

// 批次二（待评估）: OnAuthResult 持 notifyMutex_ 调用外部 callback 是反模式（持锁回调可能死锁）。
// 但 notifyMutex_ 不能简单移除——它保护 callback_ 捕获的 promise 资源的生命周期：
// ClearCallBack 必须等 OnAuthResult 执行完才能销毁 promise，否则 OnAuthResult 持有的 callback 副本
// 会引用已销毁的 promise → UAF。完整修复需重构为 shared_ptr<callback wrapper> 引用计数方案，
// 让 callback 执行移到锁外同时保证资源安全。当前保持现状，添加注释说明语义约束。
// SA 聚合完成后回调 → 触发 std::function → C++ 调用方或 NAPI Promise resolve
int32_t AuthResultCallbackService::OnAuthResult(const AuthResult &result)
{
    // notifyMutex_ 串行化回调执行 + 保护 callback_ 捕获的 promise 资源生命周期（防止 ClearCallBack 并发销毁 promise）
    std::lock_guard<ffrt::mutex> execLock(mutexes_->notifyMutex_);
    std::function<void(const AuthResult &result)> callback;
    {
        // callbackMutex_ 仅保护 callback_ 变量的读写，临界区极短
        std::lock_guard<ffrt::mutex> slotLock(mutexes_->callbackMutex_);
        callback = callback_;
    }
    if (callback == nullptr) {
        SGLOGE("callback is null");
        return FAILED;
    }
    SGLOGD("OnAuthResult mergedStrategy=%{public}d", static_cast<int32_t>(result.GetMergedAuthStrategy()));
    callback(result);  // 持 notifyMutex_ 执行：保证 ClearCallBack 等待回调完成后再销毁 promise
    return SUCCESS;
}
} // namespace OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
