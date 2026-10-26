/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "auth_event_callback_service.h"

#include <cinttypes>
#include <memory>

#include "ffrt.h"
#include "security_guard_define.h"
#include "security_guard_log.h"

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
namespace OHOS::Security::SecurityGuard {
// 每实例独立锁：跨实例不互相阻塞。锁实现仅在 cpp 内可见，头文件不暴露 ffrt。
// 锁序：notifyMutex_ -> callbackMutex_，反向获取视为死锁。
struct AuthEventCallbackService::CallbackMutex {
    ffrt::mutex notifyMutex_;
    ffrt::mutex callbackMutex_;
};

AuthEventCallbackService::AuthEventCallbackService()
    : mutexes_(std::make_unique<CallbackMutex>()) {}

AuthEventCallbackService::~AuthEventCallbackService() = default;

void AuthEventCallbackService::RegistCallBack(std::function<void(const AuthEvent &event)> callback)
{
    std::lock_guard<ffrt::mutex> lock(mutexes_->callbackMutex_);
    if (callback == nullptr) {
        return;
    }
    callback_ = callback;
}

void AuthEventCallbackService::ClearCallBack()
{
    // OnAuthEvent 在"拷贝回调 + 执行用户回调"整段期间都持有 notifyMutex_，
    // 因此这里取 notifyMutex_ 即可等待本 stub 上所有在途 OnAuthEvent 跑完整段。
    // 锁序为 notifyMutex_ -> callbackMutex_，与 OnAuthEvent 一致，不会死锁。
    std::lock_guard<ffrt::mutex> execLock(mutexes_->notifyMutex_);
    std::lock_guard<ffrt::mutex> slotLock(mutexes_->callbackMutex_);
    callback_ = nullptr;
}

int32_t AuthEventCallbackService::OnAuthEvent(const AuthEvent &event, int64_t seqnum)
{
    std::lock_guard<ffrt::mutex> execLock(mutexes_->notifyMutex_);
    std::function<void(const AuthEvent &event)> callback;
    {
        std::lock_guard<ffrt::mutex> slotLock(mutexes_->callbackMutex_);
        callback = callback_;
    }
    if (callback == nullptr) {
        SGLOGE("callback is null");
        return FAILED;
    }
    SGLOGD("OnAuthEvent eventId=%{public}" PRId64 ", seqnum=%{public}" PRId64, event.GetEventId(), seqnum);
    
    AuthEvent eventWithSeqnum = event;
    eventWithSeqnum.SetSeqnum(seqnum);
    callback(eventWithSeqnum);
    return SUCCESS;
}
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
