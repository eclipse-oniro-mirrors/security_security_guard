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

#ifndef SECURITY_GUARD_DATA_COLLECT_MANAGER_SERVICE_H
#define SECURITY_GUARD_DATA_COLLECT_MANAGER_SERVICE_H

#include <future>

#include "nocopyable.h"
#include "system_ability.h"
#include "data_collection.h"
#include "ffrt.h"
#include "i_db_listener.h"
#include "i_model_info.h"
#include "data_collect_manager_idl_stub.h"
#include "security_guard_define.h"
#include "security_event_query_callback_proxy.h"
namespace OHOS::Security::SecurityGuard {
class DataCollectManagerService : public SystemAbility, public DataCollectManagerIdlStub, public NoCopyable {
DECLARE_SYSTEM_ABILITY(DataCollectManagerService);

public:
    DataCollectManagerService(int32_t saId, bool runOnCreate);
    ~DataCollectManagerService() override = default;
    void OnStart() override;
    void OnStop() override;
    int Dump(int fd, const std::vector<std::u16string>& args) override;
    ErrCode RequestDataSubmit(int64_t eventId, const std::string &version, const std::string &time,
        const std::string &content) override;
    ErrCode RequestDataSubmitAsync(int64_t eventId, const std::string &version, const std::string &time,
        const std::string &content) override;
    ErrCode RequestRiskData(const std::string &devId, const std::string &eventList,
        const sptr<IRemoteObject> &cb) override;
    ErrCode Subscribe(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &cb, const std::string &clientId) override;
    ErrCode Unsubscribe(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &cb, const std::string &clientId) override;
    ErrCode QuerySecurityEvent(const std::vector<SecurityCollector::SecurityEventRuler> &rulers,
        const sptr<IRemoteObject> &cb, const std::string &eventGroup) override;
    ErrCode CollectorStart(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &cb) override;
    ErrCode CollectorStop(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &cb) override;
        ErrCode ConfigUpdate(int fd, const std::string& name) override;
    ErrCode QuerySecurityEventConfig(std::string &result) override;
    ErrCode AddFilter(const SecurityEventFilter &subscribeMute, const std::string &clientId) override;
    ErrCode RemoveFilter(const SecurityEventFilter &subscribeMute, const std::string &clientId) override;
    ErrCode Subscribe(int64_t eventId, const std::string &clientId) override;
    ErrCode Unsubscribe(int64_t eventId, const std::string &clientId) override;
    ErrCode CreatClient(const std::string &eventGroup, const std::string &clientId,
        const sptr<IRemoteObject> &cb) override;
    ErrCode DestoryClient(const std::string &eventGroup, const std::string &clientId) override;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    ErrCode QuerySecurityEventById(const std::vector<SecurityCollector::SecurityEventRuler> &rulers,
        const sptr<IRemoteObject> &cb, const std::string &eventGroup) override;
    ErrCode QueryCodeSignInfoByPath(const int fd, const int pid, std::string &resStr) override;
private:
    class SubscriberDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit SubscriberDeathRecipient(wptr<DataCollectManagerService> service) : service_(service) {}
        ~SubscriberDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override ;
    private:
        wptr<DataCollectManagerService> service_{};
    };
    void DumpEventInfo(int fd, int64_t eventId);
    static std::vector<SecEvent> GetSecEventsFromConditions(RequestCondition &condition);
    static void PushDataCollectTask(const sptr<IRemoteObject> &object, std::string conditions, std::string devId,
        std::shared_ptr<std::promise<int32_t>> promise);
    static bool QueryEventByRuler(sptr<ISecurityEventQueryCallback> proxy,
        SecurityCollector::SecurityEventRuler ruler);
    static int32_t QueryEventConfig(std::string &result);
    int32_t WriteRemoteFileToLocal(int fd, const std::string &realPath);
    int32_t IsApiHasPermission(const std::string &api);
    int32_t IsEventGroupHasPermission(const std::string &eventGroup, std::vector<int64_t> eventIds);
    int32_t IsEventGroupHasPublicPermission(const std::string &eventGroup, std::vector<int64_t> eventIds);
    bool ParseTrustListFile(const std::string &trustListFile);
    int32_t SetDeathCallBack(SgSubscribeEvent event, const sptr<IRemoteObject> &callback);
    static void QuerySecurityEventCallBack(sptr<ISecurityEventQueryCallback> proxy,
        std::vector<SecurityCollector::SecurityEvent> events);
    std::mutex mutex_ {};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_{};
    std::map<std::string,  sptr<IRemoteObject>> clientCallBacks_ {};
    std::atomic<int32_t> tokenBucket_{};
};
} // namespace OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_DATA_COLLECT_MANAGER_SERVICE_H