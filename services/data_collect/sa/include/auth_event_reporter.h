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

#ifndef SECURITY_GUARD_AUTH_EVENT_REPORTER_H
#define SECURITY_GUARD_AUTH_EVENT_REPORTER_H
#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE

#include <cstdint>
#include <string>

namespace OHOS::Security::SecurityGuard {
// HA 打点适配层（AuthEvent 框架专用）。
// 通过dlopen/dlsym 获取 sg_ext 仓 EventWrapper 实例完成HA上报
class AuthEventReporter {
public:
    static void ReportAuthBlockResult(int64_t eventId, int32_t callerUid, int64_t beginTime, int64_t seqnum,
        const std::string &resultExtra);
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
#endif // SECURITY_GUARD_AUTH_EVENT_REPORTER_H
