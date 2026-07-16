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

#ifndef SECURITY_GUARD_ACQUIRE_DATA_SUBSCIBEE_SUBSCRIBE_INFO_H
#define SECURITY_GUARD_ACQUIRE_DATA_SUBSCIBEE_SUBSCRIBE_INFO_H

#include <map>
#include <unordered_set>
#include <mutex>
#include <set>

#include "ffrt.h"
#include "iremote_object.h"
#include "timer.h"
#include "tokenid_kit.h"
#include "accesstoken_kit.h"
#include "i_db_listener.h"
#include "security_collector_subscribe_info.h"
#include "os_account_manager.h"
#include "i_collector_subscriber.h"
#include "i_collector_fwk.h"
#include "i_event_filter.h"
#include "i_event_wrapper.h"
#include "security_event_filter.h"
#include "security_event_info.h"
namespace OHOS::Security::SecurityGuard {
typedef SecurityCollector::IEventFilter* (*GetEventFilterFunc)();
typedef SecurityCollector::IEventWrapper* (*GetEventWrapperFunc)();
class AcquireDataSubscribeManager {
public:
    static AcquireDataSubscribeManager& GetInstance();
    int InsertSubscribeRecord(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
        const sptr<IRemoteObject> &callback, const std::string &clientId);
    int RemoveSubscribeRecord(int64_t eventId, const sptr<IRemoteObject> &callback, const std::string &clientId);
    int InsertSubscribeRecord(int64_t eventId, const std::string &clientId);
    void StartClearEventCache();
    void StopClearEventCache();
    int RemoveSubscribeRecord(int64_t eventId, const std::string &clientId);
    bool PublishEventToSub(const SecurityCollector::Event &event);
    void RemoveSubscribeRecordOnRemoteDied(const sptr<IRemoteObject> &callback);
    int InsertSubscribeMute(const EventMuteFilter &filter, const std::string &clientId);
    int RemoveSubscribeMute(const EventMuteFilter &filter, const std::string &clientId);
    int CreatClient(const std::string &eventGroup, const std::string &clientId, const sptr<IRemoteObject> &cb);
    int DestoryClient(const std::string &eventGroup, const std::string &clientId);
    void SubscriberEventOnSgStart();
    std::string GetCurrentClientGroup(const std::string &clientId);
    class ClientSession {
    public:
        pid_t pid {};
        sptr<IRemoteObject> callback {};
        std::string clientId {};
        std::map<int64_t, std::vector<EventMuteFilter>> eventFilters {};
        std::set<int64_t> subEvents{};
        std::string eventGroup {};
        int64_t uid {-1};
        std::string procName {};
    };
    void StartTokenBucketTask();
    void StopTokenBucketTask();
    int UploadEvent(const SecurityCollector::Event &event);
    void DeInitDeviceId();
    void InitEventQueue();
    void DeInitEventQueue();
    const std::map<std::string, std::shared_ptr<ClientSession>> &GetAuditClientSessionMap();
private:
    AcquireDataSubscribeManager();
    ~AcquireDataSubscribeManager();
    void InitUserId();
    void InitDeviceId();
    int SubscribeSc(int64_t eventId);
    int UnSubscribeSc(int64_t eventId);
    int SubscribeScInSg(int64_t eventId, uint32_t isSticky);
    int SubscribeScInSc(int64_t eventId);
    size_t GetSecurityCollectorEventBufSize(const SecurityCollector::Event &event);
    SecurityCollector::SecurityCollectorEventMuteFilter ConvertFilter(const SecurityGuard::EventMuteFilter &sgFilter,
        const std::string &clientId);
    int RemoveMute(const EventMuteFilter &filter, const std::string &clientId);
    int InsertMute(const EventMuteFilter &filter, const std::string &clientId);
    int CheckInsertMute(const EventMuteFilter &filter, const std::string &clientId);
    int IsExceedLimited(const std::string &clientId, const std::string &eventGroup, pid_t callerPid);
    bool IsFindFlag(const std::set<std::string> &eventSubscribes, int64_t eventId, const std::string &clientId);
    void NotifySub(sptr<IRemoteObject> obj, const SecurityCollector::Event &events);
    void ClearEventCache();
    void UploadEventToStore(const SecurityCollector::Event &event);
    void UploadEventToSub(const SecurityCollector::Event &event);
    void UploadEventTask(const SecurityCollector::Event &event);
    int UploadEventImmediately(const SecurityCollector::Event &event);
    int BatchUploadEvent(const SecurityCollector::Event &event);
    class DbListener : public IDbListener {
    public:
        DbListener() = default;
        ~DbListener() override = default;
        void OnChange(uint32_t optType, const SecEvent &events,
            const std::set<std::string> &eventSubscribes) override;
    };
    class SecurityCollectorSubscriber : public SecurityCollector::ICollectorSubscriber {
    public:
        explicit SecurityCollectorSubscriber(
            SecurityCollector::Event event) : SecurityCollector::ICollectorSubscriber(event) {};
        ~SecurityCollectorSubscriber() override = default;
        int32_t OnNotify(const SecurityCollector::Event &event) override;
    };
    class CollectorListener : public SecurityCollector::ICollectorFwk {
    public:
        void OnNotify(const SecurityCollector::Event &event) override;
        std::string GetExtraInfo() override;
        void InsertCallingUids(uint32_t callingUid);
    private:
        ffrt::mutex callingUidsMutex_{};
        std::unordered_set<uint32_t> callingUids_;
    };
    std::shared_ptr<CollectorListener> collectorListener_{};
    std::unordered_map<int64_t, std::shared_ptr<SecurityCollectorSubscriber>> scSubscribeMap_{};
    std::map<int64_t, std::shared_ptr<SecurityCollector::ICollectorFwk>> eventToListenner_;
    void *handle_ = nullptr;
    void *wrapperHandle_ = nullptr;
    GetEventFilterFunc eventFilter_ = nullptr;
    GetEventWrapperFunc eventWrapper_ = nullptr;
    bool isStopClearCache_ = false;
    ffrt::mutex clearCachemutex_ {};
    ffrt::mutex userIdMutex_ {};
    ffrt::mutex queueMutex_ {};
    ffrt::mutex dbQueueMutex_ {};
    std::string deviceId_ {};
    int32_t userId_ {-1};
    ffrt::mutex sessionMutex_{};
    ffrt::mutex eventsMutex_{};
    std::map<std::string, std::shared_ptr<AcquireDataSubscribeManager::ClientSession>> sessionsMap_ {};
    std::shared_ptr<ffrt::queue> queue_{};
    std::shared_ptr<ffrt::queue> crucialQueue_{};
    std::vector<SecEvent> events_ {};
    std::vector<SecurityCollector::Event> notifyEvents_ {};
    size_t eventsBuffSize_ {};
    std::atomic<int32_t> tokenBucket_{};
    bool isStopTokenBucketTask_ = false;
    std::map<std::string, std::set<int64_t>> reportedStickyEvents_;
    bool HasStickyEventReported(int64_t eventId, const std::string &clientId);
    bool MarkStickyEventReported(int64_t eventId, const std::string &clientId);
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_ACQUIRE_DATA_SUBSCIBEE_SUBSCRIBE_INFO_H