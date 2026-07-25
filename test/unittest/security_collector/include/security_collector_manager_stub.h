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

#ifndef SECURITY_GUARD_SECURITY_COLLECTOR_MANAGER_STUB_H
#define SECURITY_GUARD_SECURITY_COLLECTOR_MANAGER_STUB_H

#include "iremote_stub.h"

#include "i_security_collector_manager.h"
#include "i_collector_subscriber.h"

namespace OHOS::Security::SecurityCollector {
class SecurityCollectorManagerStub : public IRemoteStub<ISecurityCollectorManager> {
public:
    SecurityCollectorManagerStub() = default;
    ~SecurityCollectorManagerStub() override = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
        MessageOption& option) override;

private:
    int32_t HandleSubscribeCmd(MessageParcel &data, MessageParcel &reply);
    int32_t HandleUnsubscribeCmd(MessageParcel &data, MessageParcel &reply);
    int32_t HandleStartCmd(MessageParcel &data, MessageParcel &reply);
    int32_t HandleStopCmd(MessageParcel &data, MessageParcel &reply);
    int32_t HandleSecurityEventQueryCmd(MessageParcel &data, MessageParcel &reply);
    int32_t HandleSecurityEventQueryBatchCmd(MessageParcel &data, MessageParcel &reply);
    int32_t ReadQueryBatchRequest(MessageParcel &data, std::vector<SecurityEventRuler> &rulers);
    int32_t WriteQueryBatchReply(MessageParcel &reply, int32_t ret,
        const std::vector<SecurityCollector::SecurityEvent> &events, const std::vector<int64_t> &failedEventIds);
    int32_t HandleMute(MessageParcel &data, MessageParcel &reply);
    int32_t HandleUnmute(MessageParcel &data, MessageParcel &reply);
    std::shared_ptr<ICollectorSubscriber> UnMarshalSubscriber(MessageParcel &data);
};
} // namespace OHOS::Security::SecurityCollector

#endif // SECURITY_GUARD_SECURITY_COLLECTOR_MANAGER_H
