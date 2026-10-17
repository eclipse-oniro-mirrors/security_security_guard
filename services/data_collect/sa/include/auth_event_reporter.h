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

#include "auth_event.h"

namespace OHOS::Security::SecurityGuard {
// HA 打点适配层（AuthEvent 框架专用）。
// 真实上报走 ha_client_lite_api.h（HA lite 客户端），该头文件依赖尚未进入本仓构建环境，
// 接入点集中在 auth_event_reporter.cpp 的 ReportToHa()，接入时仅需修改该函数，
// 上层打点语义（事件名/字段）不受影响。
class AuthEventReporter {
public:
    // 阻断结果回填打点：SetAuthResult 且 allowFlag=false 时上报。
    // 内容：应用信息（caller pid/uid）+ 事件信息（eventId/content/metadata）+ 发送时间。
    static void ReportAuthBlockResult(pid_t callerPid, int32_t callerUid, const AuthEvent &event);
    // 超时打点：Client 超时未回填时上报。
    // 内容：应用信息（caller pid/uid）+ 事件信息（eventId/content/metadata）+ 超时时间。
    static void ReportTimeoutResult(pid_t callerPid, int32_t callerUid,
        int64_t eventId, const std::string &content, const std::string &metadata, int64_t timeoutMs);

private:
    // HA lite 客户端真实上报的统一接入点：ha_client_lite_api.h 依赖进入本仓构建环境后，
    // 仅修改本函数完成接入（组装 eventName + 参数键值对并上报），上层打点语义不受影响。
    static void ReportToHa(const char *eventName, pid_t callerPid, int32_t callerUid,
        int64_t eventId, const std::string &content, const std::string &metadata,
        int64_t timeoutMs, int64_t sendTimeMs);
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
#endif // SECURITY_GUARD_AUTH_EVENT_REPORTER_H
