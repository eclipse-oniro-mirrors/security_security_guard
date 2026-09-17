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

#ifndef REQUEST_SECURITY_EVENT_INFO_NAPI_H
#define REQUEST_SECURITY_EVENT_INFO_NAPI_H
#include <map>
#include "event_info.h"
#include "event_define.h"
#include "security_guard_define.h"
#include "system_ability_load_callback_stub.h"
#include "security_event_query_callback.h"
#include "security_event_ruler.h"
#include "i_collector_subscriber.h"
#include "acquire_data_manager_callback_service.h"
#include "sg_classify_client.h"
#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
#include "auth_event_info.h"
#include "auth_provider_subscribe_client.h"
#include "auth_result.h"
#endif
namespace OHOS::Security::SecurityGuard {
class SecurityGuardSdkAdaptor {
public:
    static int32_t RequestSecurityEventInfo(std::string &devId, std::string &eventList,
        RequestRiskDataCallback callback);
    static int32_t InnerRequestSecurityModelResult(const std::string &devId, uint32_t modelId,
        const std::string &param, SecurityGuardRiskCallback callback);
    static int32_t InnerReportSecurityInfo(const std::shared_ptr<EventInfo> &info);
    static int32_t StartCollector(const SecurityCollector::Event &event, int64_t duration);
    static int32_t StopCollector(const SecurityCollector::Event &event);
    static int32_t QuerySecurityEvent(std::vector<SecurityCollector::SecurityEventRuler> rulers,
        std::shared_ptr<SecurityEventQueryCallback> callback);
    static int32_t Subscribe(const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &subscriber);
    static int32_t Unsubscribe(const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &subscriber);
    static int32_t ConfigUpdate(const SecurityGuard::SecurityConfigUpdateInfo &updateInfo);
#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
    static int32_t CreateProvider(AuthProviderCallback callback, const std::string &serviceId,
        std::shared_ptr<AuthProviderSubscribeClient> &provider);
    static int32_t RequestAuthResult(std::shared_ptr<AuthProviderSubscribeClient> provider,
        const AuthEventInfo &event, AuthResult &result);
#endif
private:
    SecurityGuardSdkAdaptor() = delete;
    ~SecurityGuardSdkAdaptor() = delete;
};
} // OHOS::Security::SecurityGuard

#endif // REQUEST_SECURITY_EVENT_INFO_NAPI_H