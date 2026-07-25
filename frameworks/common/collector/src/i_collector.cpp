/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "i_collector.h"

namespace OHOS::Security::SecurityCollector {
int ICollector::Query(const SecurityEventRuler &ruler, std::vector<SecurityEvent> &events)
{
    return 0;
};
int ICollector::BatchQuery(const std::vector<SecurityEventRuler> &rulers,
    std::vector<SecurityEvent> &events, std::vector<int64_t> &failedEventIds)
{
    for (const auto &ruler : rulers) {
        std::vector<SecurityEvent> tempEvents;
        int ret = Query(ruler, tempEvents);
        if (ret != 0) {
            failedEventIds.push_back(ruler.GetEventId());
            continue;
        }
        events.insert(events.end(), tempEvents.begin(), tempEvents.end());
    }
    return 0;
};
int ICollector::Subscribe(std::shared_ptr<ICollectorFwk> api, int64_t eventId)
{
    return 0;
};
int ICollector::Unsubscribe(int64_t eventId)
{
    return 0;
};
int ICollector::IsStartWithSub()
{
    return 0;
};
} // namespace OHOS::Security::SecurityCollector