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

#ifndef SECURITY_GUARD_SECURITY_COLLECTOR_MANAGER_SERVICE_H
#define SECURITY_GUARD_SECURITY_COLLECTOR_MANAGER_SERVICE_H

#include <mutex>
#include "nocopyable.h"
#include "system_ability.h"

#include "security_collector_subscriber_manager.h"
#include "security_collector_manager_callback_proxy.h"
#include "security_collector_manager_stub.h"
#include "security_collector_define.h"
namespace OHOS::Security::SecurityCollector {
class SecurityCollectorManagerService : public SystemAbility, public SecurityCollectorManagerStub, public NoCopyable {
DECLARE_SYSTEM_ABILITY(SecurityCollectorManagerService);

public:
    class SubscriberDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        SubscriberDeathRecipient(wptr<SecurityCollectorManagerService> service) : service_(service) {}
        ~SubscriberDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override ;
    private:
        wptr<SecurityCollectorManagerService> service_{};
    };
    SecurityCollectorManagerService(int32_t saId, bool runOnCreate);
    ~SecurityCollectorManagerService() override = default;
    void OnStart() override;
    void OnStop() override;
    int Dump(int fd, const std::vector<std::u16string>& args) override;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

    int32_t Subscribe(const SecurityCollectorSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &callback) override;
    int32_t Unsubscribe(const sptr<IRemoteObject> &callback) override;
    int32_t CollectorStop(const SecurityCollectorSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &callback) override;
    int32_t CollectorStart(const SecurityCollectorSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &callback) override;
    int32_t QuerySecurityEvent(const std::vector<SecurityEventRuler> rulers,
        std::vector<SecurityEvent> &events) override;
    static void ReportScSubscribeEvent(const ScSubscribeEvent &event);
    static void ReportScUnsubscribeEvent(const ScUnsubscribeEvent &event);
private:
    static std::string GetAppName();
    static int32_t HasPermission(const std::string &permission);
    bool SetDeathRecipient(const sptr<IRemoteObject> &remote);
    void UnsetDeathRecipient(const sptr<IRemoteObject> &remote);
    void CleanSubscriber(const sptr<IRemoteObject> &remote);
    void ExecuteOnNotifyByTask(const sptr<IRemoteObject> &remote, const Event &event);
    int32_t CollectorStartInner(const std::string &appName,
        const SecurityCollectorSubscribeInfo &subscribeInfo, const Event &event);
    std::mutex deathRecipientMutex_{};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_{};
};
} // namespace OHOS::Security::SecurityCollector
#endif // SECURITY_GUARD_SECURITY_COLLECTOR_MANAGER_SERVICE_H
