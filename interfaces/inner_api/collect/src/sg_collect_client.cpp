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

#include "data_collect_manager_proxy.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "sg_collect_client.h"

namespace OHOS::Security::SecurityGuard {
int32_t NativeDataCollectKit::ReportSecurityInfo(const std::shared_ptr<EventInfo> &info)
{
    if (info == nullptr) {
        return BAD_PARAM;
    }
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        return NULL_OBJECT;
    }
    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<DataCollectManagerProxy>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is nullptr");
        return NULL_OBJECT;
    }
    int32_t ret = proxy->RequestDataSubmit(info->GetEventId(), info->GetVersion(),
        SecurityGuardUtils::GetData(), info->GetContent());
    if (ret != SUCCESS) {
        SGLOGE("RequestSecurityInfo error, ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}
}

static int32_t ReportSecurityInfoImpl(const struct EventInfoSt *info)
{
    if (info == nullptr || info->contentLen >= CONTENT_MAX_LEN) {
        return OHOS::Security::SecurityGuard::BAD_PARAM;
    }
    int64_t eventId = info->eventId;
    std::string version = reinterpret_cast<const char *>(info->version);
    uint8_t tmp[CONTENT_MAX_LEN] = {};
    (void) memset_s(tmp, CONTENT_MAX_LEN, 0, CONTENT_MAX_LEN);
    errno_t rc = memcpy_s(tmp, CONTENT_MAX_LEN, info->content, info->contentLen);
    if (rc != EOK) {
        return OHOS::Security::SecurityGuard::NULL_OBJECT;
    }
    std::string content(reinterpret_cast<const char *>(tmp));
    auto eventInfo = std::make_shared<OHOS::Security::SecurityGuard::EventInfo>(eventId, version, content);
    return OHOS::Security::SecurityGuard::NativeDataCollectKit::ReportSecurityInfo(eventInfo);
}

#ifdef __cplusplus
extern "C" {
#endif

int32_t ReportSecurityInfo(const struct EventInfoSt *info)
{
    return ReportSecurityInfoImpl(info);
}

#ifdef __cplusplus
}
#endif