/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "iservice_registry.h"
#include "securec.h"

#include "data_collect_manager_idl_proxy.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "sg_collect_client.h"
#include "data_collect_manager.h"

namespace OHOS::Security::SecurityGuard {
int32_t NativeDataCollectKit::ReportSecurityInfo(const std::shared_ptr<EventInfo> &info)
{
    return DataCollectManager::GetInstance().ReportSecurityEvent(info, true);
}

int32_t NativeDataCollectKit::ReportSecurityInfoAsync(const std::shared_ptr<EventInfo> &info)
{
    return DataCollectManager::GetInstance().ReportSecurityEvent(info, false);
}

int32_t NativeDataCollectKit::SecurityGuardConfigUpdate(int32_t fd, const std::string &name)
{
    return DataCollectManager::GetInstance().SecurityGuardConfigUpdate(fd, name);
}

}  // namespace OHOS::Security::SecurityGuard

static int32_t ReportSecurityInfoImpl(const struct EventInfoSt *info, bool isSync)
{
    if (info == nullptr || info->contentLen >= CONTENT_MAX_LEN || info->version == nullptr) {
        return OHOS::Security::SecurityGuard::BAD_PARAM;
    }
    constexpr size_t VERSION_MAX_LNE = 50;
    int64_t eventId = info->eventId;
    size_t versionLen = strnlen(info->version, VERSION_MAX_LNE);
    if (versionLen == 0 ||versionLen >= VERSION_MAX_LNE) {
        return OHOS::Security::SecurityGuard::BAD_PARAM;
    }
    std::string version(info->version, versionLen);
    uint8_t tmp[CONTENT_MAX_LEN] = {};
    (void)memset_s(tmp, CONTENT_MAX_LEN, 0, CONTENT_MAX_LEN);
    errno_t rc = memcpy_s(tmp, CONTENT_MAX_LEN, info->content, info->contentLen);
    if (rc != EOK) {
        return OHOS::Security::SecurityGuard::NULL_OBJECT;
    }
    std::string content(reinterpret_cast<const char *>(tmp));
    auto eventInfo = std::make_shared<OHOS::Security::SecurityGuard::EventInfo>(eventId, version, content);
    if (isSync) {
        return OHOS::Security::SecurityGuard::NativeDataCollectKit::ReportSecurityInfo(eventInfo);
    } else {
        return OHOS::Security::SecurityGuard::NativeDataCollectKit::ReportSecurityInfoAsync(eventInfo);
    }
}

#ifdef __cplusplus
extern "C" {
#endif

int32_t ReportSecurityInfo(const struct EventInfoSt *info)
{
    return ReportSecurityInfoImpl(info, true);
}

int32_t ReportSecurityInfoAsync(const struct EventInfoSt *info)
{
    return ReportSecurityInfoImpl(info, false);
}

int32_t SecurityGuardConfigUpdate(int32_t fd, const char *fileName)
{
    if (fileName == nullptr) {
        return OHOS::Security::SecurityGuard::BAD_PARAM;
    }
    return OHOS::Security::SecurityGuard::NativeDataCollectKit::SecurityGuardConfigUpdate(fd, fileName);
}
#ifdef __cplusplus
}
#endif