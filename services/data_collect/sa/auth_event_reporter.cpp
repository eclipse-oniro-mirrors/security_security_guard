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

#include <chrono>
#include <cinttypes>
#include <string>

#include "security_guard_log.h"

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
namespace OHOS::Security::SecurityGuard {
namespace {
    // HA 事件名（接入 ha_client_lite_api.h 时沿用）
    constexpr const char* AUTH_BLOCK_RESULT_EVENT = "AUTH_BLOCK_RESULT";
    constexpr const char* AUTH_TIMEOUT_EVENT = "AUTH_BLOCK_TIMEOUT";
}

void AuthEventReporter::ReportAuthBlockResult(pid_t callerPid, int32_t callerUid, const AuthEvent &event)
{
    // M14: 采集发送时间（应用下发阻断结果的时刻）
    auto sendTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    ReportToHa(AUTH_BLOCK_RESULT_EVENT, callerPid, callerUid, event.GetEventId(),
        event.GetContent(), event.GetMetadata(), 0, sendTimeMs);
}

void AuthEventReporter::ReportTimeoutResult(pid_t callerPid, int32_t callerUid,
    int64_t eventId, const std::string &content, const std::string &metadata, int64_t timeoutMs)
{
    auto sendTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    ReportToHa(AUTH_TIMEOUT_EVENT, callerPid, callerUid, eventId, content, metadata, timeoutMs, sendTimeMs);
}

void AuthEventReporter::ReportToHa(const char *eventName, pid_t callerPid, int32_t callerUid,
    int64_t eventId, const std::string &content, const std::string &metadata,
    int64_t timeoutMs, int64_t sendTimeMs)
{
    // HA lite 客户端真实上报的统一入口（依赖 ha_client_lite_api.h 进入本仓构建环境后
    // 在此组装并上报：eventName + CALLER_PID/CALLER_UID/EVENT_ID/CONTENT/METADATA/SEND_TIME/TIMEOUT_MS）。
    // 注意：HA 上报若为耗时接口，仅允许锁外调用（与 Notify 推送同纪律）。
    SGLOGI("ha report, event=%{public}s, pid=%{public}d, uid=%{public}d, eventId=%{public}" PRId64
        ", timeoutMs=%{public}" PRId64 ", sendTimeMs=%{public}" PRId64,
        eventName, static_cast<int32_t>(callerPid), callerUid, eventId, timeoutMs, sendTimeMs);
    SGLOGD("ha report detail, content=%{public}s, metadata=%{public}s", content.c_str(), metadata.c_str());
}
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
