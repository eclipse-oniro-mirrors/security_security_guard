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

#include "auth_event_reporter.h"
#include <cinttypes>
#include <dlfcn.h>
#include <string>

#include "i_event_wrapper.h"
#include "security_guard_log.h"

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
namespace OHOS::Security::SecurityGuard {
namespace {
typedef SecurityCollector::IEventWrapper* (*GetEventWrapperFunc)();
GetEventWrapperFunc GetEventWrapperEntry()
{
    static GetEventWrapperFunc func = []() -> GetEventWrapperFunc {
        void *handle = dlopen(SECURITY_GUARD_EVENT_WRAPPER_PATH, RTLD_LAZY);
        if (handle == nullptr) {
            SGLOGE("dlopen event wrapper failed");
            return nullptr;
        }
        auto entry = reinterpret_cast<GetEventWrapperFunc>(dlsym(handle, "GetEventWrapper"));
        if (entry == nullptr) {
            SGLOGI("dlsym GetEventWrapper failed");
            return nullptr;
        }
        SGLOGE("dlopen event wrapper success");
        return entry;
    }();
    return func;
}
} // namespace

void AuthEventReporter::ReportAuthBlockResult(int64_t eventId, int32_t callerUid, int64_t beginTime, int64_t seqnum,
    const std::string &resultExtra)
{
    auto entry = GetEventWrapperEntry();
    if (entry == nullptr) {
        SGLOGE("event wrapper not available, skip HA reprot");
        return;
    }

    auto wrapper = entry();
    if (wrapper == nullptr) {
        SGLOGE("event wrapper instance is null, skip HA reprot");
        return;
    }
    SGLOGD("report auth block result, event=%{public}" PRId64 ", seqnum=%{public}" PRId64 ", uid=%{public}d, "
           "beginTime=%{public}" PRId64, eventId, seqnum, callerUid, beginTime);
    wrapper->RecordAuthBlockResult(eventId, callerUid, beginTime, seqnum, resultExtra);
}
} // namespace OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
