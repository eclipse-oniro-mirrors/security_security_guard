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

#ifndef SECURITY_COLLECTOR_MANAGER_H
#define SECURITY_COLLECTOR_MANAGER_H

#include <map>
#include <mutex>
#include "singleton.h"
#include "security_collector_manager_callback_service.h"
#include "i_collector_subscriber.h"
#include "security_event_ruler.h"
#include "security_event.h"
namespace OHOS::Security::SecurityCollector {
class CollectorManager : public Singleton<CollectorManager> {
public:
    class DeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        DeathRecipient() = default;
        ~DeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    };
    int32_t Subscribe(const std::shared_ptr<ICollectorSubscriber> &subscriber);
    int32_t Unsubscribe(const std::shared_ptr<ICollectorSubscriber> &subscriber);
    int32_t QuerySecurityEvent(const std::vector<SecurityEventRuler> rulers,
        std::vector<SecurityEvent> &events);
    int32_t CollectorStart(const SecurityCollector::SecurityCollectorSubscribeInfo &subscriber);
    int32_t CollectorStop(const SecurityCollector::SecurityCollectorSubscribeInfo &subscriber);
private:
    void HandleDecipient();
    int32_t SubscribeImpl(const std::shared_ptr<ICollectorSubscriber> &subscriber);
    int32_t UnsubscribeImpl(const std::shared_ptr<ICollectorSubscriber> &subscriber);
    int32_t QuerySecurityEventImpl(const std::vector<SecurityEventRuler> rulers,
        std::vector<SecurityEvent> &events);
    int32_t CollectorStartImpl(const SecurityCollector::SecurityCollectorSubscribeInfo &subscriber);
    int32_t CollectorStopImpl(const SecurityCollector::SecurityCollectorSubscribeInfo &subscriber);
    std::mutex mutex_{};
    std::map<std::shared_ptr<ICollectorSubscriber>, sptr<SecurityCollectorManagerCallbackService>> eventListeners_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_{};
};
} // namespace OHOS::Security::SecurityCollector
#endif // SECURITY_COLLECTOR_MANAGER_H