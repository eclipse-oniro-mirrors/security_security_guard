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

#ifndef SECURITY_GUARD_COLLECTOR_MANAGER_MOCK_H
#define SECURITY_GUARD_COLLECTOR_MANAGER_MOCK_H

#include "gmock/gmock.h"

#include "security_event_ruler.h"
#include "security_collector_subscribe_info.h"
#include "security_event.h"

namespace OHOS::Security::SecurityCollector {
class BaseCollectorManager {
public:
    virtual ~BaseCollectorManager() = default;
    virtual int32_t Subscribe(const std::shared_ptr<ICollectorSubscriber> &subscriber) = 0;
    virtual int32_t Unsubscribe(const std::shared_ptr<ICollectorSubscriber> &subscriber) = 0;
    virtual int32_t QuerySecurityEvent(const std::vector<SecurityEventRuler> &rulers,
        std::vector<SecurityEvent> &events) = 0;
    virtual int32_t QuerySecurityEventBatch(const std::vector<SecurityEventRuler> &rulers,
        std::vector<SecurityEvent> &events, std::vector<int64_t> &failedEventIds) = 0;
    virtual int32_t CollectorStart(const SecurityCollector::SecurityCollectorSubscribeInfo &subscriber) = 0;
    virtual int32_t CollectorStop(const SecurityCollector::SecurityCollectorSubscribeInfo &subscriber) = 0;
};

class CollectorManager : public BaseCollectorManager {
public:
    static CollectorManager &GetInstance()
    {
        static CollectorManager instance;
        return instance;
    };
    CollectorManager() = default;
    ~CollectorManager() override = default;
    MOCK_METHOD1(Subscribe, int32_t(const std::shared_ptr<ICollectorSubscriber> &subscriber));
    MOCK_METHOD1(Unsubscribe, int32_t(const std::shared_ptr<ICollectorSubscriber> &subscriber));
    MOCK_METHOD2(QuerySecurityEvent, int32_t(const std::vector<SecurityEventRuler> &rulers,
        std::vector<SecurityEvent> &events));
    MOCK_METHOD3(QuerySecurityEventBatch, int32_t(const std::vector<SecurityEventRuler> &rulers,
        std::vector<SecurityEvent> &events, std::vector<int64_t> &failedEventIds));
    MOCK_METHOD1(CollectorStart, int32_t(const SecurityCollector::SecurityCollectorSubscribeInfo &subscriber));
    MOCK_METHOD1(CollectorStop, int32_t(const SecurityCollector::SecurityCollectorSubscribeInfo &subscriber));
};
} // OHOS::Security::SecurityCollector

#endif // SECURITY_GUARD_COLLECTOR_MANAGER_MOCK_H