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

#include "acquire_data_manager_callback_service.h"
#include <cinttypes>
#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {

int32_t AcquireDataManagerCallbackService::OnNotify(const SecurityCollector::Event &event)
{
    std::lock_guard<std::mutex> lock(mutex_);
    SGLOGD("callback eventId=%{public}" PRId64, event.eventId);
    for (auto iter : subscribers) {
        if ((iter->GetSubscribeInfo().GetEventGroup() == "security_event" ||
            iter->GetSubscribeInfo().GetEventGroup() == "") &&
            iter->GetSubscribeInfo().GetEvent().eventId == event.eventId) {
            iter->OnNotify(event);
        }
    }
    return SUCCESS;
}

int32_t AcquireDataManagerCallbackService::BatchOnNotify(const std::vector<SecurityCollector::Event> &events)
{
    std::lock_guard<std::mutex> lock(mutex_);
    SGLOGD("BatchOnNotify callback");
    for (auto it : events) {
        for (auto iter : subscribers) {
            if (iter->GetSubscribeInfo().GetEventGroup() == "audit_event" &&
                iter->GetSubscribeInfo().GetEvent().eventId == it.eventId) {
                iter->OnNotify(it);
            }
        }
    }
    return SUCCESS;
}
}