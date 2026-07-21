/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SECURITY_GUARD_SECURITY_COLLECTOR_SUBSCRIBLER_MANAGER_H
#define SECURITY_GUARD_SECURITY_COLLECTOR_SUBSCRIBLER_MANAGER_H

#include <map>
#include <set>
#include <mutex>
#include <memory>
#include "timer.h"
#include "ffrt.h"
#include "i_collector_fwk.h"
#include "i_event_filter.h"
#include "i_event_wrapper.h"
#include "security_collector_subscriber.h"

namespace OHOS::Security::SecurityCollector {
typedef SecurityCollector::IEventFilter* (*GetEventFilterFunc)();
typedef SecurityCollector::IEventWrapper* (*GetEventWrapperFunc)();
class SecurityCollectorSubscriberManager {
public:
    static SecurityCollectorSubscriberManager &GetInstance();
    using UnsubscribeHandler = std::function<void (const sptr<IRemoteObject> &remote)>;
    bool SubscribeCollector(const std::shared_ptr<SecurityCollectorSubscriber> &subscriber);
    bool UnsubscribeCollector(const sptr<IRemoteObject> &remote);
    void SetUnsubscribeHandler(UnsubscribeHandler handler) { unsubscribeHandler_ = handler; }
    void RemoveAllFilter();
private:
    SecurityCollectorSubscriberManager();
    ~SecurityCollectorSubscriberManager();
    auto FindSecurityCollectorSubscribers(const sptr<IRemoteObject> &remote);
    std::set<int64_t> FindEventIds(const sptr<IRemoteObject> &remote);
    int32_t GetAppSubscribeCount(const std::string &appName);
    int32_t GetAppSubscribeCount(const std::string &appName, int64_t eventId);
    bool CleanSubscriber(const sptr<IRemoteObject> &remote)
    {
        unsubscribeHandler_(remote);
        return true;
    }
    void NotifySubscriber(const Event &event);

    class CollectorListenner : public ICollectorFwk {
    public:
        CollectorListenner(const std::shared_ptr<SecurityCollectorSubscriber> &subscriber) : subscriber_(subscriber) {}
        std::string GetExtraInfo() override;
        int64_t GetEventId() override;
        void OnNotify(const Event &event) override;
    private:
        std::shared_ptr<SecurityCollectorSubscriber> subscriber_;
    };

    UnsubscribeHandler unsubscribeHandler_{};
    ffrt::mutex collectorMutex_{};
    std::map<int64_t, std::set<std::shared_ptr<SecurityCollectorSubscriber>>> eventToSubscribers_{};
    std::map<int64_t, std::shared_ptr<ICollectorFwk>> eventToListenner_;
    std::shared_ptr<ICollectorFwk> collectorListenner_{};
    void *handle_ = nullptr;
    void *wrapperHandle_ = nullptr;
    GetEventFilterFunc eventFilter_ = nullptr;
    GetEventWrapperFunc eventWrapper_ = nullptr;
};
}
#endif // SECURITY_GUARD_SECURITY_COLLECTOR_SUBSCRIBLER_MANAGER_H