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

#include "security_guard_sdk_adaptor.h"
#include <cinttypes>
#include "data_collect_manager.h"
#include "sg_collect_client.h"
#include "sg_classify_client.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
int32_t SecurityGuardSdkAdaptor::RequestSecurityEventInfo(std::string &devId, std::string &eventList,
    RequestRiskDataCallback callback)
{
    SGLOGI("enter SecurityGuardSdkAdaptor RequestSecurityEventInfo");
    return DataCollectManager::GetInstance().RequestSecurityEventInfo(devId, eventList, callback);
}

int32_t SecurityGuardSdkAdaptor::InnerRequestSecurityModelResult(const std::string &devId, uint32_t modelId,
    const std::string &param, SecurityGuardRiskCallback callback)
{
    SGLOGI("enter SecurityGuardSdkAdaptor InnerRequestSecurityModelResult");
    return RequestSecurityModelResultAsync(devId, modelId, param, callback);
}

int32_t SecurityGuardSdkAdaptor::InnerReportSecurityInfo(const std::shared_ptr<EventInfo> &info)
{
    SGLOGD("enter SecurityGuardSdkAdaptor InnerReportSecurityInfo");
    return  DataCollectManager::GetInstance().ReportSecurityEvent(info, true);
}

int32_t SecurityGuardSdkAdaptor::StartCollector(const SecurityCollector::Event &event,
    int64_t duration)
{
    SGLOGI("enter SecurityGuardSdkAdaptor StartCollector");
    return DataCollectManager::GetInstance().StartCollector(event, duration);
}

int32_t SecurityGuardSdkAdaptor::StopCollector(const SecurityCollector::Event &event)
{
    SGLOGI("in SecurityGuardSdkAdaptor StopCollector");
    return DataCollectManager::GetInstance().StopCollector(event);
}

int32_t SecurityGuardSdkAdaptor::QuerySecurityEvent(std::vector<SecurityCollector::SecurityEventRuler> rulers,
    std::shared_ptr<SecurityEventQueryCallback> callback)
{
    SGLOGI("enter SecurityGuardSdkAdaptor QuerySecurityEvent");
    return DataCollectManager::GetInstance().QuerySecurityEvent(rulers, callback);
}

int32_t SecurityGuardSdkAdaptor::Subscribe(const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &subscriber)
{
    SGLOGI("enter SecurityGuardSdkAdaptor Subscribe");
    return DataCollectManager::GetInstance().Subscribe(subscriber);
}

int32_t SecurityGuardSdkAdaptor::Unsubscribe(const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &subscriber)
{
    SGLOGI("enter SecurityGuardSdkAdaptor Unsubscribe");
    return DataCollectManager::GetInstance().Unsubscribe(subscriber);
}

int32_t SecurityGuardSdkAdaptor::ConfigUpdate(const SecurityGuard::SecurityConfigUpdateInfo &updateInfo)
{
    SGLOGI("enter SecurityGuardSdkAdaptor ConfigUpdate");
    return DataCollectManager::GetInstance().SecurityGuardConfigUpdate(updateInfo.GetFd(), updateInfo.GetFileName());
}

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
int32_t SecurityGuardSdkAdaptor::CreateProvider(AuthProviderCallback callback, const std::string &serviceId,
    std::shared_ptr<AuthProviderSubscribeClient> &provider)
{
    SGLOGI("SecurityGuardSdkAdaptor CreateProvider, serviceId=%{public}s", serviceId.c_str());
    return AuthProviderSubscribeClient::CreateProvider(callback, serviceId, provider);
}

int32_t SecurityGuardSdkAdaptor::RequestAuthResult(std::shared_ptr<AuthProviderSubscribeClient> provider,
    const AuthEventInfo &event, AuthResultCallback callback)
{
    SGLOGI("SecurityGuardSdkAdaptor RequestAuthResult, eventId=%{public}" PRId64, event.GetEventId());
    if (provider == nullptr) {
        return BAD_PARAM;
    }
    return provider->RequestAuthResult(event, callback);
}
#endif
} // OHOS::Security::SecurityGuard