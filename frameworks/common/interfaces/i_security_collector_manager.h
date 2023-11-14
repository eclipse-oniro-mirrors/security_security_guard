/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef ISECURITY_COLLECTOR_MANAGER_H
#define ISECURITY_COLLECTOR_MANAGER_H

#include <cstdint>
#include <cstring>

#include "iremote_broker.h"

#include "event_define.h"
#include "security_collector_subscribe_info.h"
#include "security_collector_manager_service_ipc_interface_code.h"

namespace OHOS::Security::SecurityCollector {
constexpr int32_t SECURITY_COLLECTOR_MANAGER_SA_ID = 3525;

class ISecurityCollectorManager : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Security.SecurityCollectorManager");
    using InterfaceCode = SecurityCollectManagerInterfaceCode;
    enum {
        CMD_COLLECTOR_SUBCRIBE = static_cast<uint32_t>(InterfaceCode::CMD_COLLECTOR_SUBCRIBE),
        CMD_COLLECTOR_UNSUBCRIBE = static_cast<uint32_t>(InterfaceCode::CMD_COLLECTOR_UNSUBCRIBE)
    };

    virtual int32_t Subscribe(const SecurityCollectorSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &callback) = 0;
    virtual int32_t Unsubscribe(const sptr<IRemoteObject> &callback) = 0;
};

class ISecurityCollectorManagerCallback : public IRemoteBroker {
public:
    using InterfaceCode = SecurityCollectManagerCallbackInterfaceCode;
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Security.SecurityCollectorManager.Callback");
    enum {
        CMD_COLLECTOR_NOTIFY = static_cast<uint32_t>(InterfaceCode::CMD_COLLECTOR_CALLBACK)
    };

    virtual int32_t OnNotify(const Event &event) = 0;
};

} // namespace OHOS::Security::SecurityCollector

#endif // ISECURITY_COLLECTOR_MANAGER_H
