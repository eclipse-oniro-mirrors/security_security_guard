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

#ifndef SECURITY_GUARD_DATA_COLLECT_MANAGER_H
#define SECURITY_GUARD_DATA_COLLECT_MANAGER_H

#include <map>
#include <mutex>
#include "i_collector_subscriber.h"
#include "security_event_query_callback.h"
#include "security_event_ruler.h"
#include "acquire_data_manager_callback_service.h"
#include "event_info.h"
namespace OHOS::Security::SecurityGuard {
class DataCollectManager {
public:
    static DataCollectManager& GetInstance();
    class DeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        DeathRecipient() = default;
        ~DeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    };
    int32_t ReportSecurityEvent(const std::shared_ptr<EventInfo> &info, bool isSync);
    int32_t SecurityGuardConfigUpdate(int32_t fd, const std::string &name);
    int32_t Subscribe(const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &subscriber);
    int32_t Unsubscribe(const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &subscriber);
    int32_t QuerySecurityEvent(std::vector<SecurityCollector::SecurityEventRuler> rulers,
        std::shared_ptr<SecurityEventQueryCallback> callback);
    int32_t QuerySecurityEvent(std::vector<SecurityCollector::SecurityEventRuler> rulers,
        std::shared_ptr<SecurityEventQueryCallback> callback, const std::string &eventGroup);
    int32_t QuerySecurityEventConfig(std::string &result);
    int32_t StartCollector(const SecurityCollector::Event &event, int64_t duration);
    int32_t StopCollector(const SecurityCollector::Event &event);
    int32_t RequestSecurityEventInfo(std::string &devId, std::string &eventList, RequestRiskDataCallback callback);
    int32_t QuerySecurityEventById(std::vector<SecurityCollector::SecurityEventRuler> rulers,
        std::shared_ptr<SecurityEventQueryCallback> callback, const std::string &eventGroup);
    int32_t QueryCodeSignInfoByPath(const std::string &filePath, std::string &result);
private:
    DataCollectManager();
    ~DataCollectManager() = default;
    void HandleDecipient();
    bool IsCurrentSubscriberEventIdExist(const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &sub);
    int32_t SetDeathRecipient(const sptr<IRemoteObject> &remote);
    std::mutex mutex_{};
    sptr<AcquireDataManagerCallbackService> callback_{};
    std::string sdkFlag_{};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_{};
    std::set<std::shared_ptr<SecurityCollector::ICollectorSubscriber>> subscribers_{};
    uint32_t count_ = 0;
};
}  // namespace OHOS::Security::SecurityGuard
#endif  // SECURITY_GUARD_DATA_COLLECT_MANAGER_H