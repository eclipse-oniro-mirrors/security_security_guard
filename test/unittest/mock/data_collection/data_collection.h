/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef DATA_COLLECTION_MOCK_H
#define DATA_COLLECTION_MOCK_H

#include "gmock/gmock.h"
#include "parcel.h"

#include <vector>

#include "lib_loader.h"
#include "i_collector_fwk.h"
#include "security_event.h"

namespace OHOS::Security::SecurityCollector {
class BaseDataCollection {
public:
    virtual ~BaseDataCollection() = default;
    virtual bool StartCollectors(const std::vector<int64_t>& eventIds, std::shared_ptr<ICollectorFwk> api) = 0;
    virtual bool StopCollectors(const std::vector<int64_t>& eventIds) = 0;
    virtual int SubscribeCollectors(const std::vector<int64_t>& eventIds, std::shared_ptr<ICollectorFwk> api) = 0;
    virtual int SubscribeCollectorsBySticky(const std::vector<int64_t> &eventIds,
        std::shared_ptr<ICollectorFwk> api) = 0;
    virtual int UnsubscribeCollectors(const std::vector<int64_t>& eventIds) = 0;
    virtual ErrorCode GetCollectorType(int64_t eventId, int32_t& collectorType) = 0;
    virtual int32_t QuerySecurityEvent(const std::vector<SecurityEventRuler> rulers,
        std::vector<SecurityEvent> &events) = 0;
    virtual int32_t QuerySecurityEventConfig(std::string &result) = 0;
    virtual bool SecurityGuardSubscribeCollector(const std::vector<int64_t>& eventIds) = 0;
};

class DataCollection : public BaseDataCollection {
public:
    static DataCollection &GetInstance()
    {
        static DataCollection instance;
        return instance;
    };
    DataCollection() = default;
    ~DataCollection() override = default;
    MOCK_METHOD2(StartCollectors, bool(const std::vector<int64_t>& eventIds, std::shared_ptr<ICollectorFwk> api));
    MOCK_METHOD1(StopCollectors, bool(const std::vector<int64_t>& eventIds));
    MOCK_METHOD2(SubscribeCollectors, int(const std::vector<int64_t>& eventIds,
        std::shared_ptr<ICollectorFwk> api));
    MOCK_METHOD2(SubscribeCollectorsBySticky, int(const std::vector<int64_t>& eventIds,
        std::shared_ptr<ICollectorFwk> api));
    MOCK_METHOD1(UnsubscribeCollectors, int(const std::vector<int64_t>& eventIds));
    MOCK_METHOD2(GetCollectorType, ErrorCode(int64_t eventId, int32_t& collectorType));
    MOCK_METHOD2(QuerySecurityEvent, int32_t(const std::vector<SecurityEventRuler> rulers,
        std::vector<SecurityEvent> &events));
    MOCK_METHOD1(QuerySecurityEventConfig, int32_t(std::string &result));
    MOCK_METHOD1(SecurityGuardSubscribeCollector, bool(const std::vector<int64_t>& eventIds));
    void CloseLib() {};
};
}
#endif // DATA_COLLECTION_MOCK_H