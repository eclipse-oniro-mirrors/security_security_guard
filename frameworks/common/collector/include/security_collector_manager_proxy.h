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

#ifndef SECURITY_GUARD_SECURITY_COLLECTOR_MANAGER_PROXY_H
#define SECURITY_GUARD_SECURITY_COLLECTOR_MANAGER_PROXY_H

#include <string>

#include "iremote_object.h"
#include "iremote_proxy.h"
#include "nocopyable.h"

#include "i_security_collector_manager.h"
namespace OHOS::Security::SecurityCollector {
class SecurityCollectorManagerProxy : public IRemoteProxy<ISecurityCollectorManager>, public NoCopyable {
public:
    explicit SecurityCollectorManagerProxy(const sptr<IRemoteObject> &impl);
    ~SecurityCollectorManagerProxy() override = default;

    int32_t Subscribe(const SecurityCollectorSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &callback) override;
    int32_t Unsubscribe(const sptr<IRemoteObject> &callback) override;
    int32_t CollectorStart(const SecurityCollectorSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &callback) override;
    int32_t CollectorStop(const SecurityCollectorSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &callback) override;
    int32_t QuerySecurityEvent(const std::vector<SecurityEventRuler> &rulers,
        std::vector<SecurityEvent> &events) override;
    int32_t QuerySecurityEventBatch(const std::vector<SecurityEventRuler> &rulers,
        std::vector<SecurityEvent> &events, std::vector<int64_t> &failedEventIds) override;
private:
    int32_t WriteQueryBatchRequest(MessageParcel &data, const std::vector<SecurityEventRuler> &rulers);
    int32_t ReadQueryBatchReply(MessageParcel &reply, std::vector<SecurityEvent> &events,
        std::vector<int64_t> &failedEventIds);
    static inline BrokerDelegator<SecurityCollectorManagerProxy> delegator_;
};
} // namespace OHOS::Security::SecurityCollector

#endif // SECURITY_GUARD_SECURITY_COLLECTOR_MANAGER_PROXY_H
