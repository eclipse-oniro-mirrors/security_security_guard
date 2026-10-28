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

#include "acquire_data_subscribe_manager.h"
#include <cinttypes>
#include <functional>
#include "file_ex.h"
#include "ipc_skeleton.h"
#include "acquire_data_callback_proxy.h"
#include "database_manager.h"
#include "security_guard_define.h"
#include "security_collector_subscribe_info.h"
#include "security_guard_log.h"
#ifdef SECURITY_GUARD_ENABLE_DEVICE_ID
#include "device_manager.h"
#endif
#include "ffrt.h"
#include "ffrt_inner.h"
#include "event_define.h"
#include "i_model_info.h"
#include "config_data_manager.h"
#include "collector_manager.h"
#include "data_collection.h"
#include "security_event_filter.h"
#include "security_event_info.h"
#include "data_format.h"
#include "data_statistics.h"
#include "security_guard_utils.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr size_t MAX_CACHE_EVENT_SIZE = 64;
    constexpr int64_t MAX_DURATION_TEN_SECOND = 1 * 1000;
    constexpr size_t MAX_SESSION_SIZE = 16;
    constexpr size_t MAX_SESSION_SIZE_ONE_PROCESS = 2;
    constexpr size_t MAX_CACHE_NOTIFY_EVENT_SIZE = 10;
#ifdef SECURITY_GUARD_ENABLE_DEVICE_ID
    constexpr const char *PKG_NAME = "ohos.security.securityguard";
#endif
#ifdef SECURITY_GUARD_DEVICE_TYPE_PC
    constexpr int UPLOAD_EVENT_TASK_MAX_COUNT = 6000;
#else
    constexpr int UPLOAD_EVENT_TASK_MAX_COUNT = 500;
#endif

    std::atomic<uint32_t> g_taskCount = 0;
    std::atomic<uint32_t> g_crucialTaskCount = 0;
    constexpr int32_t TOKEN_BUCKET_STEP_SIZE = 500;
    constexpr int32_t TOKEN_BUCKET_MAX_SIZE = TOKEN_BUCKET_STEP_SIZE * 10 * 60;
    constexpr int32_t TOKEN_BUCKET_INTERVAL_TIME = 1000;
    constexpr int64_t FILE_EVENT_ID = 0x01C000007;
    constexpr uint32_t PUBLISH_EVENT_TO_SUB_STEP_COUNT = 100;
    constexpr int64_t PUBLISH_EVENT_TO_SUB_STEP_TIME = 100;
#ifdef SECURITY_GUARD_ENABLE_DEVICE_ID
    constexpr int32_t DEVICE_ID_RECOVERY_INIT_INTERVAL_SEC = 1;
    constexpr int32_t DEVICE_ID_RECOVERY_MAX_INTERVAL_SEC = 30;
#endif
    ffrt::thread g_tokenBucketThread {};
    ffrt::thread g_cleanEventCacheThread {};

    bool IsSameMuteFilter(const EventMuteFilter &a, const EventMuteFilter &b)
    {
        return a.eventId == b.eventId && a.isInclude == b.isInclude &&
            a.type == b.type && a.mutes.size() == b.mutes.size() && a.mutes == b.mutes;
    }
}

#ifdef SECURITY_GUARD_ENABLE_DEVICE_ID
class InitCallback : public DistributedHardware::DmInitCallback {
public:
    ~InitCallback() override = default;
    void OnRemoteDied() override
    {
        // 设备管理服务死亡：失效缓存并按退避自动重新注册获取
        AcquireDataSubscribeManager::GetInstance().RecoverDeviceId();
    };
};
#endif

AcquireDataSubscribeManager& AcquireDataSubscribeManager::GetInstance()
{
    static AcquireDataSubscribeManager instance;
    return instance;
}

AcquireDataSubscribeManager::AcquireDataSubscribeManager() : collectorListener_(std::make_shared<CollectorListener>())
{
    handle_ = dlopen(SECURITY_GUARD_EVENT_FILTER_PATH, RTLD_LAZY);
    if (handle_ != nullptr) {
        eventFilter_ = reinterpret_cast<GetEventFilterFunc>(dlsym(handle_, "GetEventFilter"));
    }
    wrapperHandle_ = dlopen(SECURITY_GUARD_EVENT_WRAPPER_PATH, RTLD_LAZY);
    if (wrapperHandle_ != nullptr) {
        eventWrapper_ = reinterpret_cast<GetEventWrapperFunc>(dlsym(wrapperHandle_, "GetEventWrapper"));
    }
    if (eventFilter_ == nullptr) {
        SGLOGI("eventFilter_ is nullptr");
    }
    if (eventWrapper_ == nullptr) {
        SGLOGI("eventWrapper_ is nullptr");
    }
    events_.reserve(MAX_CACHE_EVENT_SIZE);
}

AcquireDataSubscribeManager::~AcquireDataSubscribeManager()
{
    // 兜底：静态析构前先收敛 deviceId 恢复线程，避免线程访问已析构成员
#ifdef SECURITY_GUARD_ENABLE_DEVICE_ID
    StopDeviceIdRecovery();
#endif
    if (handle_ != nullptr) {
        dlclose(handle_);
        handle_ = nullptr;
    }
    if (wrapperHandle_ != nullptr) {
        dlclose(wrapperHandle_);
        wrapperHandle_ = nullptr;
    }
}

int AcquireDataSubscribeManager::InsertSubscribeRecord(int64_t eventId, const std::string &clientId)
{
    AcquireDataSubscribeManager::GetInstance().InitUserId();
    AcquireDataSubscribeManager::GetInstance().RefreshDeviceIdAsync();
    std::vector<EventMuteFilter> filtersToSet {};
    {
        std::lock_guard<ffrt::mutex> lock(sessionMutex_);
        if (sessionsMap_.find(clientId) == sessionsMap_.end() || sessionsMap_.at(clientId) == nullptr) {
            SGLOGI("not find current clientId");
            return BAD_PARAM;
        }
        if (sessionsMap_.at(clientId)->subEvents.find(eventId) != sessionsMap_.at(clientId)->subEvents.end()) {
            SGLOGE("not need subscribe again");
            return SUCCESS;
        }
        // 先落账，外部订阅失败时回滚
        sessionsMap_.at(clientId)->subEvents.insert(eventId);
        auto it = sessionsMap_.at(clientId)->eventFilters.find(eventId);
        if (it != sessionsMap_.at(clientId)->eventFilters.end()) {
            filtersToSet = it->second;
        }
    }
    // 锁外执行订阅（内部由 subscribeMutex_ 串行并基于最新会话状态重查）
    int32_t code = SubscribeScIfNeeded(eventId);
    if (code != SUCCESS) {
        std::lock_guard<ffrt::mutex> lock(sessionMutex_);
        auto it = sessionsMap_.find(clientId);
        if (it != sessionsMap_.end() && it->second != nullptr) {
            it->second->subEvents.erase(eventId);
        }
        SGLOGE("SubscribeSc error");
        return code;
    }
    for (const auto &filter : filtersToSet) {
        // 下发前复查：并发 RemoveSubscribeMute 已删除的过滤不再下发
        if (!IsFilterInSession(clientId, filter)) {
            continue;
        }
        InsertMute(filter, clientId);
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::InsertSubscribeRecord(
    const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &callback,
    const std::string &clientId)
{
    pid_t callerPid = IPCSkeleton::GetCallingPid();
    int64_t eventId = subscribeInfo.GetEvent().eventId;
    std::string eventGroup = subscribeInfo.GetEventGroup();
    AcquireDataSubscribeManager::GetInstance().InitUserId();
    AcquireDataSubscribeManager::GetInstance().RefreshDeviceIdAsync();
    bool sessionCreated = false;
    {
        std::lock_guard<ffrt::mutex> lock(sessionMutex_);
        if (sessionsMap_.find(clientId) != sessionsMap_.end() && sessionsMap_.at(clientId) != nullptr &&
            sessionsMap_.at(clientId)->subEvents.find(eventId) != sessionsMap_.at(clientId)->subEvents.end()) {
            SGLOGE("not need subscribe again");
            return SUCCESS;
        }
        if (sessionsMap_.find(clientId) == sessionsMap_.end() || sessionsMap_.at(clientId) == nullptr) {
            auto session = std::make_shared<ClientSession>();
            session->clientId = clientId;
            session->callback = callback;
            session->pid = callerPid;
            session->eventGroup = eventGroup;
            sessionsMap_[clientId] = session;
            sessionCreated = true;
        }
        sessionsMap_.at(clientId)->subEvents.insert(eventId);
    }
    int32_t code = SubscribeScIfNeeded(eventId);
    if (eventWrapper_ != nullptr && eventGroup == "auditGroup") {
        eventWrapper_()->RecordSubscribeEvent(eventId, code, IPCSkeleton::GetCallingUid());
    }
    if (code != SUCCESS) {
        std::lock_guard<ffrt::mutex> lock(sessionMutex_);
        auto it = sessionsMap_.find(clientId);
        if (it != sessionsMap_.end() && it->second != nullptr) {
            it->second->subEvents.erase(eventId);
            if (sessionCreated && it->second->subEvents.empty()) {
                sessionsMap_.erase(clientId);
            }
        }
        SGLOGE("SubscribeSc error");
        return code;
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::RemoveSubscribeRecord(int64_t eventId, const sptr<IRemoteObject> &callback,
    const std::string &clientId)
{
    // cleanupSession=true：会话无订阅后删除会话并清理 sticky 记录（兼容原回调版本语义）
    return RemoveSubscribeRecordCore(eventId, clientId, true);
}

int AcquireDataSubscribeManager::InsertMute(const EventMuteFilter &filter, const std::string &clientId)
{
    SecurityCollector::SecurityCollectorEventMuteFilter collectorFilter = ConvertFilter(filter, clientId);
    EventCfg config {};
    if (!ConfigDataManager::GetInstance().GetEventConfig(collectorFilter.eventId, config)) {
        SGLOGE("GetEventConfig error");
        return BAD_PARAM;
    }
    if (eventFilter_ == nullptr) {
        SGLOGE("eventFilter_ is null");
        return NULL_OBJECT;
    }
    int ret = eventFilter_()->SetEventFilter(collectorFilter);
    if (ret != SUCCESS) {
        SGLOGE("SetEventFilter failed, ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::SubscribeScInSg(int64_t eventId, uint32_t isSticky)
{
    SecurityCollector::Event event {};
    event.eventId = eventId;
    SGLOGI("Scheduling start collector, eventId:%{public}" PRId64, eventId);
    if (eventToListenner_.count(eventId) != 0) {
        return SUCCESS;
    }
    if (collectorListener_ == nullptr) {
        SGLOGE("collectorListener is nullptr");
        return NULL_OBJECT;
    }
    int32_t ret = SUCCESS;
    if (isSticky == 0) {
        ret = SecurityCollector::DataCollection::GetInstance().SubscribeCollectors({eventId}, collectorListener_);
        // In consideration of compatibility， only return KERNEL_NOT_SUPPORT
        if (ret == KERNEL_NOT_SUPPORT) {
            SGLOGI("Subscribe SG failed, eventId=%{public}" PRId64, eventId);
            return ret;
        }
        if (ret != SUCCESS) {
            SGLOGI("Subscribe SG failed, eventId=%{public}" PRId64 ", ret=%{public}d", eventId, ret);
            return FAILED;
        }
        eventToListenner_.emplace(eventId, collectorListener_);
    } else {
        ret = SecurityCollector::DataCollection::GetInstance().SubscribeCollectorsBySticky({eventId},
            collectorListener_);
        if (ret == KERNEL_NOT_SUPPORT) {
            SGLOGI("Subscribe Sticky SG failed, eventId=%{public}" PRId64, eventId);
            return ret;
        }
        if (ret != SUCCESS) {
            SGLOGI("Subscribe Sticky SG failed, eventId=%{public}" PRId64 ", ret=%{public}d", eventId, ret);
            return FAILED;
        }
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::SubscribeScInSc(int64_t eventId)
{
    if (scSubscribeMap_.count(eventId) != 0) {
        return SUCCESS;
    }
    SecurityCollector::Event scEvent;
    scEvent.eventId = eventId;
    auto subscriber = std::make_shared<AcquireDataSubscribeManager::SecurityCollectorSubscriber>(scEvent);
    int code = SecurityCollector::CollectorManager::GetInstance().Subscribe(subscriber);
    if (code != SUCCESS) {
        SGLOGI("Subscribe SC failed, code=%{public}d", code);
        return code;
    }
    scSubscribeMap_[eventId] = subscriber;
    return SUCCESS;
}

int AcquireDataSubscribeManager::SubscribeSc(int64_t eventId)
{
    EventCfg config {};
    bool isSuccess = ConfigDataManager::GetInstance().GetEventConfig(eventId, config);
    if (!isSuccess) {
        SGLOGE("GetEventConfig error");
        return BAD_PARAM;
    }
    if (config.eventType != static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL)) {
        return SUCCESS;
    }
    collectorListener_->InsertCallingUids(static_cast<uint32_t>(IPCSkeleton::GetCallingUid()));
    // 订阅SG
    if (config.prog == "security_guard") {
        return SubscribeScInSg(eventId, config.isSticky);
    }
    // 订阅SC
    return SubscribeScInSc(eventId);
}

int AcquireDataSubscribeManager::UnSubscribeSc(int64_t eventId)
{
    EventCfg config;
    bool isSuccess = ConfigDataManager::GetInstance().GetEventConfig(eventId, config);
    if (!isSuccess) {
        SGLOGE("GetEventConfig error");
        return BAD_PARAM;
    }
    if (config.eventType != static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL)) {
        return SUCCESS;
    }
    // 解订阅SG
    if (config.prog == "security_guard") {
        if (config.isSticky == 0 && eventToListenner_.count(eventId) == 0) {
            SGLOGE("not find eventId in linstener, eventId=%{public}" PRId64, eventId);
            return FAILED;
        }
        int32_t ret = SecurityCollector::DataCollection::GetInstance().UnsubscribeCollectors({eventId});
        if (ret == KERNEL_NOT_SUPPORT) {
            SGLOGE("UnSubscribe SG failed, eventId=%{public}" PRId64, eventId);
            return ret;
        }
        if (ret != SUCCESS) {
            SGLOGI("UnSubscribe Sticky SG failed, eventId=%{public}" PRId64 ", ret=%{public}d", eventId, ret);
            return ret;
        }
        if (config.isSticky == 0) {
            eventToListenner_.erase(eventId);
        }
        return SUCCESS;
    }
    // 解订阅SC
    auto it = scSubscribeMap_.find(eventId);
    if (it == scSubscribeMap_.end()) {
        SGLOGE("event not subscribe eventId=%{public}" PRId64, eventId);
        return FAILED;
    }
    int ret = SecurityCollector::CollectorManager::GetInstance().Unsubscribe(it->second);
    if (ret != SUCCESS) {
        SGLOGE("UnSubscribe SC failed, ret=%{public}d", ret);
        return ret;
    }
    it->second = nullptr;
    scSubscribeMap_.erase(it);
    SGLOGI("UnSubscribeSc scSubscribeMap_size  %{public}zu", scSubscribeMap_.size());
    return SUCCESS;
}

bool AcquireDataSubscribeManager::IsAnySessionSubscribes(int64_t eventId)
{
    // 调用方必须持有 sessionMutex_
    for (const auto &iter : sessionsMap_) {
        if (iter.second != nullptr && iter.second->subEvents.find(eventId) != iter.second->subEvents.end()) {
            return true;
        }
    }
    return false;
}

bool AcquireDataSubscribeManager::IsFilterInSession(const std::string &clientId, const EventMuteFilter &filter)
{
    std::lock_guard<ffrt::mutex> lock(sessionMutex_);
    auto it = sessionsMap_.find(clientId);
    if (it == sessionsMap_.end() || it->second == nullptr) {
        return false;
    }
    auto fit = it->second->eventFilters.find(filter.eventId);
    if (fit == it->second->eventFilters.end()) {
        return false;
    }
    auto iter = find_if(fit->second.begin(), fit->second.end(),
        [&filter](const EventMuteFilter &item) { return IsSameMuteFilter(filter, item); });
    return iter != fit->second.end();
}

int AcquireDataSubscribeManager::SubscribeScIfNeeded(int64_t eventId)
{
    // 对外部订阅调用统一串行，并在执行前基于最新会话状态重查：
    // 若决策期间会话已被并发移除（RemoteDied/DestoryClient），则不再拉起采集器，
    // 避免"为无人订阅的事件启动采集器"的泄漏；锁序：subscribeMutex_ -> sessionMutex_。
    std::lock_guard<ffrt::mutex> lock(subscribeMutex_);
    {
        std::lock_guard<ffrt::mutex> sessionLock(sessionMutex_);
        if (!IsAnySessionSubscribes(eventId)) {
            return SUCCESS;
        }
    }
    return SubscribeSc(eventId);
}

int AcquireDataSubscribeManager::UnSubscribeScIfLast(int64_t eventId)
{
    // 与 SubscribeScIfNeeded 对称：执行前重查，若仍有会话订阅则保持采集器运行，
    // 消除"决策与执行之间新订阅到达导致误停采集器"的竞态；锁序：subscribeMutex_ -> sessionMutex_。
    std::lock_guard<ffrt::mutex> lock(subscribeMutex_);
    {
        std::lock_guard<ffrt::mutex> sessionLock(sessionMutex_);
        if (IsAnySessionSubscribes(eventId)) {
            return SUCCESS;
        }
    }
    return UnSubscribeSc(eventId);
}

int AcquireDataSubscribeManager::RemoveSubscribeRecordCore(int64_t eventId, const std::string &clientId,
    bool cleanupSession)
{
    {
        std::lock_guard<ffrt::mutex> lock(sessionMutex_);
        if (sessionsMap_.find(clientId) == sessionsMap_.end() || sessionsMap_.at(clientId) == nullptr) {
            SGLOGI("not find current clientId");
            return SUCCESS;
        }
        if (sessionsMap_.at(clientId)->subEvents.find(eventId) == sessionsMap_.at(clientId)->subEvents.end()) {
            SGLOGI("not find current eventid");
            return SUCCESS;
        }
        sessionsMap_.at(clientId)->subEvents.erase(eventId);
    }
    // 锁外退订：UnSubscribeScIfLast 内部会重查"是否还有会话订阅"，非最后一个订阅者时自动跳过
    int ret = UnSubscribeScIfLast(eventId);
    if (ret != SUCCESS) {
        SGLOGE("UnSubscribeSc fail");
        std::lock_guard<ffrt::mutex> lock(sessionMutex_);
        auto it = sessionsMap_.find(clientId);
        if (it != sessionsMap_.end() && it->second != nullptr) {
            it->second->subEvents.insert(eventId);
        }
        return ret;
    }
    std::lock_guard<ffrt::mutex> lock(sessionMutex_);
    auto it = sessionsMap_.find(clientId);
    if (it != sessionsMap_.end() && it->second != nullptr) {
        if (cleanupSession && it->second->subEvents.empty()) {
            sessionsMap_.erase(clientId);
        }
    }
    if (cleanupSession && reportedStickyEvents_.find(clientId) != reportedStickyEvents_.end()) {
        reportedStickyEvents_.at(clientId).erase(eventId);
        if (reportedStickyEvents_.at(clientId).empty()) {
            reportedStickyEvents_.erase(clientId);
        }
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::RemoveSubscribeRecord(int64_t eventId, const std::string &clientId)
{
    // cleanupSession=false：不删除会话、不清理 sticky（兼容原无回调版本语义）
    return RemoveSubscribeRecordCore(eventId, clientId, false);
}

void AcquireDataSubscribeManager::RemoveSubscribeRecordOnRemoteDied(const sptr<IRemoteObject> &callback)
{
    std::string removedClientId;
    std::set<int64_t> currentEventId {};
    {
        std::lock_guard<ffrt::mutex> lock(sessionMutex_);
        auto finder = [callback](std::pair<std::string, std::shared_ptr<ClientSession>> iter) {
            return callback == iter.second->callback;
        };
        auto iter = find_if(sessionsMap_.begin(), sessionsMap_.end(), finder);
        if (iter != sessionsMap_.end()) {
            removedClientId = iter->first;
            currentEventId = iter->second->subEvents;
            sessionsMap_.erase(iter);
        }
    }
    // 插件调用与退订均在锁外执行
    if (eventFilter_ != nullptr && !removedClientId.empty()) {
        eventFilter_()->RemoveSdkAllEventFilter(removedClientId);
    }
    for (const auto &eventId : currentEventId) {
        // 内部重查：仅当无其他会话订阅时才真正退订
        (void)UnSubscribeScIfLast(eventId);
    }
}

void AcquireDataSubscribeManager::StartClearEventCache()
{
    auto task = [this]() {
        while (true) {
            this->ClearEventCache();
            {
                std::lock_guard<ffrt::mutex> lock(clearCachemutex_);
                if (isStopClearCache_ == true) {
                    break;
                }
            }
            ffrt::this_task::sleep_for(std::chrono::milliseconds(MAX_DURATION_TEN_SECOND));
        }
    };
    g_cleanEventCacheThread = ffrt::thread(task);
}

void AcquireDataSubscribeManager::StopClearEventCache()
{
    {
        std::lock_guard<ffrt::mutex> lock(clearCachemutex_);
        isStopClearCache_ = true;
    }
    if (g_cleanEventCacheThread.joinable()) {
        g_cleanEventCacheThread.join();
    }
}

void AcquireDataSubscribeManager::ClearEventCache()
{
    std::vector<SecEvent> tmp {};
    {
        std::lock_guard<ffrt::mutex> lock(eventsMutex_);
        tmp.swap(events_);
        events_.reserve(MAX_CACHE_EVENT_SIZE);
    }

    int code = DatabaseManager::GetInstance().InsertEvent(USER_SOURCE, tmp, {});
    if (code != SUCCESS) {
        SGLOGE("insert event error, %{public}d", code);
    }
    std::vector<SecurityCollector::Event> notifyTmp {};
    {
        std::lock_guard<ffrt::mutex> lock(eventsMutex_);
        notifyTmp.swap(notifyEvents_);
        notifyEvents_.reserve(MAX_CACHE_NOTIFY_EVENT_SIZE);
    }
    for (const auto &iter : notifyTmp) {
        AcquireDataSubscribeManager::GetInstance().UploadEventTask(iter);
    }
}

std::string AcquireDataSubscribeManager::GetCurrentClientGroup(const std::string &clientId)
{
    std::lock_guard<ffrt::mutex> lock(sessionMutex_);
    if (sessionsMap_.find(clientId) == sessionsMap_.end()) {
        return "";
    }
    auto session = sessionsMap_.at(clientId);
    if (session == nullptr) {
        return "";
    }
    return sessionsMap_.at(clientId)->eventGroup;
}

void AcquireDataSubscribeManager::InitUserId()
{
    int32_t id = -1;
    int32_t code = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(id);
    if (code != ERR_OK) {
        SGLOGE("GetForegroundOsAccountLocalId Fail");
        return;
    }
    std::lock_guard<ffrt::mutex> lock(userIdMutex_);
    userId_ = id;
}

void AcquireDataSubscribeManager::InitDeviceId()
{
#ifdef SECURITY_GUARD_ENABLE_DEVICE_ID
    bool expected = false;
    if (isDeviceManagerInit_.compare_exchange_strong(expected, true)) {
        auto callback = std::make_shared<InitCallback>();
        int32_t ret = DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(PKG_NAME, callback);
        if (ret != SUCCESS) {
            SGLOGI("init device manager failed, result is %{public}d", ret);
            isDeviceManagerInit_ = false;
            return;
        }
    }

    DistributedHardware::DmDeviceInfo deviceInfo;
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceInfo(PKG_NAME, deviceInfo);
    if (ret != SUCCESS) {
        SGLOGI("get local device into error, code=%{public}d", ret);
        return;
    }
    {
        std::lock_guard<ffrt::mutex> lock(userIdMutex_);
        deviceId_ = deviceInfo.deviceId;
    }
    deviceIdValid_.store(true);
#endif
}

void AcquireDataSubscribeManager::RefreshDeviceIdAsync()
{
#ifdef SECURITY_GUARD_ENABLE_DEVICE_ID
    StartDeviceIdRecovery();
#endif
}

void AcquireDataSubscribeManager::RecoverDeviceId()
{
#ifdef SECURITY_GUARD_ENABLE_DEVICE_ID
    InvalidateDeviceId();
    StartDeviceIdRecovery();
#endif
}

void AcquireDataSubscribeManager::StartDeviceIdRecovery()
{
#ifdef SECURITY_GUARD_ENABLE_DEVICE_ID
    if (deviceIdValid_.load()) {
        return; // 缓存有效，无需重复获取
    }
    bool inFlight = false;
    if (!deviceIdRefreshInFlight_.compare_exchange_strong(inFlight, true)) {
        return; // 已有恢复在途，避免重复发起设备管理 IPC
    }
    std::lock_guard<ffrt::mutex> lock(deviceIdRecoveryMutex_);
    if (deviceIdRecoveryThread_.joinable()) {
        deviceIdRecoveryThread_.join(); // 上一轮已结束（在途标记已清），立即回收
    }
    isStopDeviceIdRecovery_.store(false);
    deviceIdRecoveryThread_ = ffrt::thread([this]() { DeviceIdRecoveryLoop(); });
#endif
}

void AcquireDataSubscribeManager::DeviceIdRecoveryLoop()
{
#ifdef SECURITY_GUARD_ENABLE_DEVICE_ID
    int32_t backoffSec = DEVICE_ID_RECOVERY_INIT_INTERVAL_SEC;
    while (!isStopDeviceIdRecovery_.load() && !deviceIdValid_.load()) {
        InitDeviceId();
        if (deviceIdValid_.load()) {
            break;
        }
        // 1 秒分片睡眠并在片间检查停止标志，保证停止等待上限约为一个分片
        for (int32_t slept = 0; slept < backoffSec && !isStopDeviceIdRecovery_.load(); slept++) {
            ffrt::this_task::sleep_for(std::chrono::seconds(1));
        }
        backoffSec = std::min(backoffSec * 2, DEVICE_ID_RECOVERY_MAX_INTERVAL_SEC);
    }
    deviceIdRefreshInFlight_.store(false);
#endif
}

void AcquireDataSubscribeManager::StopDeviceIdRecovery()
{
#ifdef SECURITY_GUARD_ENABLE_DEVICE_ID
    std::lock_guard<ffrt::mutex> lock(deviceIdRecoveryMutex_);
    isStopDeviceIdRecovery_.store(true);
    if (deviceIdRecoveryThread_.joinable()) {
        deviceIdRecoveryThread_.join();
    }
#endif
}

void AcquireDataSubscribeManager::InvalidateDeviceId()
{
#ifdef SECURITY_GUARD_ENABLE_DEVICE_ID
    deviceIdValid_.store(false);
    std::lock_guard<ffrt::mutex> lock(userIdMutex_);
    deviceId_ = "";
#endif
}

void AcquireDataSubscribeManager::DeInitDeviceId()
{
#ifdef SECURITY_GUARD_ENABLE_DEVICE_ID
    isDeviceManagerInit_.store(false);
    // 服务停止：先停恢复线程再注销，避免注销后循环继续向设备管理注册
    StopDeviceIdRecovery();
    int ret = DistributedHardware::DeviceManager::GetInstance().UnInitDeviceManager(PKG_NAME);
    if (ret != SUCCESS) {
        SGLOGE("UnInitDeviceManager fail, code =%{public}d", ret);
    }
#endif
}

void AcquireDataSubscribeManager::InitEventQueue()
{
    std::lock_guard<ffrt::mutex> lock(queueMutex_);
    if (queue_ != nullptr) {
        SGLOGI("InitEventQueue queue_ already init");
        return;
    }
    queue_ = std::make_shared<ffrt::queue>(ffrt::queue_serial, "UploadEvent");
    crucialQueue_ = std::make_shared<ffrt::queue>(ffrt::queue_serial, "UploadEventImmediately");
    SGLOGI("InitEventQueue successed");
}

void AcquireDataSubscribeManager::DeInitEventQueue()
{
    std::lock_guard<ffrt::mutex> lock(queueMutex_);
    queue_ = nullptr;
    crucialQueue_ = nullptr;
}
void AcquireDataSubscribeManager::StartTokenBucketTask()
{
    auto task = [this]() {
        while (!isStopTokenBucketTask_) {
            if (tokenBucket_.load() < TOKEN_BUCKET_MAX_SIZE) {
                tokenBucket_.fetch_add(TOKEN_BUCKET_STEP_SIZE);
            }
            ffrt::this_task::sleep_for(std::chrono::milliseconds(TOKEN_BUCKET_INTERVAL_TIME));
        }
    };
    g_tokenBucketThread = ffrt::thread(task);
}

void AcquireDataSubscribeManager::StopTokenBucketTask()
{
    isStopTokenBucketTask_ = true;
    if (g_tokenBucketThread.joinable()) {
        g_tokenBucketThread.join();
    }
}

void AcquireDataSubscribeManager::NotifySub(sptr<IRemoteObject> obj, const SecurityCollector::Event &events)
{
    auto proxy = iface_cast<IAcquireDataCallback>(obj);
    if (proxy == nullptr) {
        SGLOGI("proxy is null");
        return;
    }
    proxy->OnNotify({events});
    SGLOGD("upload event to subscribe");
}

void AcquireDataSubscribeManager::UploadEventToSub(const SecurityCollector::Event &event)
{
    // upload to subscriber
    PublishEventToSub(event);
}

void AcquireDataSubscribeManager::UploadEventToStore(const SecurityCollector::Event &event)
{
    // upload to store
    std::vector<SecEvent> tmp {};
    {
        std::lock_guard<ffrt::mutex> lock(eventsMutex_);
        SecEvent secEvent {};
        secEvent.eventId = event.eventId;
        secEvent.version = event.version;
        secEvent.date = event.timestamp;
        secEvent.content = event.content;
        secEvent.userId = event.userId;
        events_.emplace_back(secEvent);
        if (events_.size() < MAX_CACHE_EVENT_SIZE) {
            return;
        }
        tmp.swap(events_);
        events_.reserve(MAX_CACHE_EVENT_SIZE);
    }
    int code = DatabaseManager::GetInstance().InsertEvent(USER_SOURCE, tmp, {});
    if (code != SUCCESS) {
        SGLOGE("insert event error, %{public}d", code);
    }
}

int AcquireDataSubscribeManager::UploadEvent(const SecurityCollector::Event &event)
{
    SGLOGD("UploadEvent eventid = %{public}" PRId64, event.eventId);
    SGLOGD("UploadEvent event conetnt = %{private}s", event.content.c_str());
    if (!DataFormat::CheckRiskContent(event)) {
        SGLOGE("CheckRiskContent error");
        return BAD_PARAM;
    }
    EventCfg config {};
    if (!ConfigDataManager::GetInstance().GetEventConfig(event.eventId, config)) {
        SGLOGE("GetEventConfig fail eventId=%{public}" PRId64, event.eventId);
        return BAD_PARAM;
    }
    if (config.isBatchUpload != 1) {
        return UploadEventImmediately(event);
    }
    return BatchUploadEvent(event);
}

int AcquireDataSubscribeManager::BatchUploadEvent(const SecurityCollector::Event &event)
{
    std::vector<SecurityCollector::Event> tmp {};
    {
        std::lock_guard<ffrt::mutex> lock(eventsMutex_);
        notifyEvents_.emplace_back(event);
        if (notifyEvents_.size() < MAX_CACHE_NOTIFY_EVENT_SIZE) {
            return SUCCESS;
        }
        tmp.swap(notifyEvents_);
        notifyEvents_.reserve(MAX_CACHE_NOTIFY_EVENT_SIZE);
    }
    auto task = [tmp]() {
        for (const auto &iter : tmp) {
            AcquireDataSubscribeManager::GetInstance().UploadEventTask(iter);
        }
        g_taskCount.fetch_sub(1);
    };
    if (g_taskCount.load() > UPLOAD_EVENT_TASK_MAX_COUNT) {
        SGLOGI("subed event be discarded id is %{public}" PRId64, event.eventId);
        return SUCCESS;
    }
    {
        std::lock_guard<ffrt::mutex> lock(queueMutex_);
        if (queue_ == nullptr) {
            return SUCCESS;
        }
        queue_->submit(task);
    }
    g_taskCount.fetch_add(1);
    return SUCCESS;
}

int AcquireDataSubscribeManager::UploadEventImmediately(const SecurityCollector::Event &event)
{
    if (g_crucialTaskCount.load() > UPLOAD_EVENT_TASK_MAX_COUNT) {
        SGLOGI("immediately subed event be discarded id is %{public}" PRId64, event.eventId);
        return SUCCESS;
    }
    g_crucialTaskCount.fetch_add(1);
    auto task = [event]() {
        AcquireDataSubscribeManager::GetInstance().UploadEventTask(event);
        g_crucialTaskCount.fetch_sub(1);
    };
    {
        std::lock_guard<ffrt::mutex> lock(queueMutex_);
        if (crucialQueue_ == nullptr) {
            g_crucialTaskCount.fetch_sub(1);
            return SUCCESS;
        }
        crucialQueue_->submit(task);
    }
    return SUCCESS;
}

void AcquireDataSubscribeManager::UploadEventTask(const SecurityCollector::Event &event)
{
    SecurityCollector::Event retEvent  = event;
    EventCfg config {};
    {
        std::lock_guard<ffrt::mutex> lock(userIdMutex_);
        retEvent.userId = userId_;
#ifdef SECURITY_GUARD_ENABLE_DEVICE_ID
        retEvent.deviceId = deviceId_;
#endif
    }
    if (!ConfigDataManager::GetInstance().GetEventConfig(retEvent.eventId, config)) {
        SGLOGE("GetEventConfig fail eventId=%{public}" PRId64, event.eventId);
        return;
    }
    if (retEvent.timestamp.empty()) {
        retEvent.timestamp = SecurityGuardUtils::GetDate();
    }
    // change old event id to new eventid
    retEvent.eventId = config.eventId;
    if (eventFilter_ != nullptr) {
        eventFilter_()->GetFlagsEventNeedToUpload(retEvent);
    }
    if (eventWrapper_ != nullptr) {
        eventWrapper_()->WrapperEvent(retEvent);
    }
    UploadEventToStore(retEvent);
    UploadEventToSub(retEvent);
}

bool AcquireDataSubscribeManager::IsFindFlag(const std::set<std::string> &eventSubscribes, int64_t eventId,
    const std::string &clientId)
{
    if (sessionsMap_.find(clientId) == sessionsMap_.end()) {
        return false;
    }
    auto session = sessionsMap_.at(clientId);
    if (session == nullptr) {
        return false;
    }
    if (session->eventFilters.find(eventId) == session->eventFilters.end() ||
        session->eventFilters.at(eventId).empty()) {
        return true;
    }
    if (eventSubscribes.find(clientId) != eventSubscribes.end()) {
        return true;
    }
    return false;
}

void AcquireDataSubscribeManager::CollectNotifyObjs(const SecurityCollector::Event &event, bool isSticky,
    std::vector<sptr<IRemoteObject>> &notifyObjs, bool &flag)
{
    std::lock_guard<ffrt::mutex> lock(sessionMutex_);
    for (auto &it : sessionsMap_) {
        if (it.second == nullptr) {
            continue;
        }
        if (it.second->subEvents.find(event.eventId) == it.second->subEvents.end()) {
            continue;
        }
        if (!IsFindFlag(event.eventSubscribes, event.eventId, it.second->clientId)) {
            continue;
        }
        if (isSticky && !MarkStickyEventReported(event.eventId, it.second->clientId)) {
            continue;
        }
        // 锁内仅快照回调对象（sptr 保活），IPC 通知在锁外进行：
        // 否则订阅端在 OnNotify 里反向调用本 SA（Subscribe/Unsubscribe/AddFilter 等）会因
        // 争抢 sessionMutex_ 而互相等待，形成重入死锁。
        notifyObjs.emplace_back(it.second->callback);
        flag = true;
    }
}

bool AcquireDataSubscribeManager::PublishEventToSub(const SecurityCollector::Event &event)
{
    static std::atomic<uint32_t> eventCount {0};
    ++eventCount;
    if (eventCount >= PUBLISH_EVENT_TO_SUB_STEP_COUNT) {
        ffrt::this_task::sleep_for(std::chrono::milliseconds(PUBLISH_EVENT_TO_SUB_STEP_TIME));
        eventCount = 0;
    }
    EventCfg config {};
    if (!ConfigDataManager::GetInstance().GetEventConfig(event.eventId, config)) {
        SGLOGE("GetEventConfig fail eventId=%{public}" PRId64, event.eventId);
        return false;
    }

    bool setCallingUidsSuccess = false;
    if (eventFilter_ != nullptr) {
        setCallingUidsSuccess = eventFilter_()->SetSubscriberUids(collectorListener_->GetExtraInfo());
    }
    if (setCallingUidsSuccess && tokenBucket_.load() <= 0 && event.eventId == FILE_EVENT_ID) {
        DataStatistics::GetInstance().IncrementPublishEvents();
        return false;
    }
    std::vector<sptr<IRemoteObject>> notifyObjs {};
    bool flag = false;
    CollectNotifyObjs(event, config.isSticky, notifyObjs, flag);
    {
        // 保持"同一时刻只向订阅端发一次 IPC"的原有语义；本锁为叶子锁，不与任何重入路径成环
        std::lock_guard<ffrt::mutex> lock(notifyMutex_);
        for (const auto &obj : notifyObjs) {
            NotifySub(obj, event);
        }
    }
    if (flag && setCallingUidsSuccess && event.eventId == FILE_EVENT_ID) {
        tokenBucket_.fetch_sub(1);
    }
    SGLOGD("publish eventid=%{public}" PRId64, event.eventId);
    for (auto iter : event.eventSubscribes) {
        SGLOGD("publish eventSubscribes =%{public}s", iter.c_str());
    }
    return true;
}

void AcquireDataSubscribeManager::CollectorListener::OnNotify(const SecurityCollector::Event &event)
{
    AcquireDataSubscribeManager::GetInstance().UploadEvent(event);
}

std::string AcquireDataSubscribeManager::CollectorListener::GetExtraInfo()
{
    std::lock_guard<ffrt::mutex> lock(callingUidsMutex_);
    std::string uidStr = "";
    for (auto uid : callingUids_) {
        if (uid == getuid()) {
            continue;
        }
        uidStr += std::to_string(uid);
    }
    return uidStr;
}

void AcquireDataSubscribeManager::CollectorListener::InsertCallingUids(uint32_t callingUid)
{
    std::lock_guard<ffrt::mutex> lock(callingUidsMutex_);
    callingUids_.insert(callingUid);
}

int32_t AcquireDataSubscribeManager::SecurityCollectorSubscriber::OnNotify(const SecurityCollector::Event &event)
{
    AcquireDataSubscribeManager::GetInstance().UploadEvent(event);
    return 0;
}

int AcquireDataSubscribeManager::CheckInsertMute(const EventMuteFilter &filter, const std::string &clientId)
{
    if (sessionsMap_.find(clientId) == sessionsMap_.end() || sessionsMap_.at(clientId) == nullptr) {
        SGLOGE("clientId not creat");
        return BAD_PARAM;
    }
    auto fit = sessionsMap_.at(clientId)->eventFilters.find(filter.eventId);
    if (fit == sessionsMap_.at(clientId)->eventFilters.end()) {
        return SUCCESS;
    }
    auto iter = find_if(fit->second.begin(), fit->second.end(),
        [&filter](const EventMuteFilter &item) { return IsSameMuteFilter(filter, item); });
    if (iter != fit->second.end()) {
        SGLOGE("filter exist");
        return BAD_PARAM;
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::InsertSubscribeMute(const EventMuteFilter &filter, const std::string &clientId)
{
    SGLOGI("in AcquireDataSubscribeManager InsertSubscribeMute, clientId %{public}s", clientId.c_str());
    bool needApply = false;
    {
        std::lock_guard<ffrt::mutex> lock(sessionMutex_);
        int ret = CheckInsertMute(filter, clientId);
        if (ret != SUCCESS) {
            SGLOGE("CheckInsertMute failed, ret=%{public}d", ret);
            return ret;
        }
        if (sessionsMap_.at(clientId)->subEvents.find(filter.eventId) == sessionsMap_.at(clientId)->subEvents.end()) {
            SGLOGW("current event not subscribe, cache filter now evetid= %{public}" PRId64, filter.eventId);
            sessionsMap_.at(clientId)->eventFilters[filter.eventId].emplace_back(filter);
            return SUCCESS;
        }
        needApply = true;
    }
    // 插件调用在锁外执行，避免持框架大锁调用 dlopen 出的第三方代码
    int ret = InsertMute(filter, clientId);
    if (ret != SUCCESS) {
        SGLOGE("InsertMute failed, ret=%{public}d", ret);
        return ret;
    }
    {
        std::lock_guard<ffrt::mutex> lock(sessionMutex_);
        auto it = sessionsMap_.find(clientId);
        if (it == sessionsMap_.end() || it->second == nullptr) {
            // 会话已被并发销毁（RemoteDied/DestoryClient），插件过滤成为孤儿，随 RemoveSdkAllEventFilter 清理
            return SUCCESS;
        }
        it->second->eventFilters[filter.eventId].emplace_back(filter);
    }
    return SUCCESS;
}

void AcquireDataSubscribeManager::SubscriberEventOnSgStart()
{
    std::vector<int64_t> eventIds = ConfigDataManager::GetInstance().GetAllEventIds();
    std::vector<int64_t> onStartEventList;
    for (int64_t eventId : eventIds) {
        EventCfg eventCfg;
        bool isSuccess = ConfigDataManager::GetInstance().GetEventConfig(eventId, eventCfg);
        if (!isSuccess) {
            SGLOGI("GetEventConfig error");
        } else if (eventCfg.collectOnStart == 1) {
            onStartEventList.push_back(eventId);
        }
    }
    if (collectorListener_ == nullptr) {
        SGLOGI("listener or collectorListener is nullptr");
        return;
    }
    if (SecurityCollector::DataCollection::GetInstance().SubscribeCollectors(onStartEventList, collectorListener_) !=
        SUCCESS) {
        SGLOGE("subscribe sg failed");
    }
}

int AcquireDataSubscribeManager::RemoveMute(const EventMuteFilter &filter, const std::string &clientId)
{
    EventCfg config {};
    SecurityCollector::SecurityCollectorEventMuteFilter collectorFilter = ConvertFilter(filter, clientId);
    if (!ConfigDataManager::GetInstance().GetEventConfig(collectorFilter.eventId, config)) {
        SGLOGE("GetEventConfig error");
        return BAD_PARAM;
    }
    if (eventFilter_ == nullptr) {
        SGLOGE("eventFilter_ is null");
        return NULL_OBJECT;
    }
    int ret = eventFilter_()->RemoveEventFilter(collectorFilter);
    if (ret != SUCCESS) {
        SGLOGE("RemoveEventFilter failed, ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::RemoveSubscribeMute(const EventMuteFilter &filter, const std::string &clientId)
{
    SGLOGI("in AcquireDataSubscribeManager RemoveSubscribeMute, clientId %{public}s", clientId.c_str());
    bool needApply = false;
    {
        std::lock_guard<ffrt::mutex> lock(sessionMutex_);
        auto it = sessionsMap_.find(clientId);
        if (it == sessionsMap_.end() || it->second == nullptr) {
            SGLOGE("clientId not creat");
            return BAD_PARAM;
        }
        auto session = it->second;
        auto fit = session->eventFilters.find(filter.eventId);
        if (fit == session->eventFilters.end()) {
            SGLOGE("filter event id not exist");
            return BAD_PARAM;
        }
        auto iter = find_if(fit->second.begin(), fit->second.end(),
            [&filter](const EventMuteFilter &item) { return IsSameMuteFilter(filter, item); });
        if (iter == fit->second.end()) {
            SGLOGE("filter not exist");
            return BAD_PARAM;
        }
        if (session->subEvents.find(filter.eventId) == session->subEvents.end()) {
            // 事件未订阅，仅删除缓存
            SGLOGW("current event not subscribe, erase filter now evetid= %{public}" PRId64, filter.eventId);
            fit->second.erase(iter);
            if (fit->second.empty()) {
                session->eventFilters.erase(filter.eventId);
            }
            return SUCCESS;
        }
        needApply = true;
    }
    // 插件调用在锁外执行
    int ret = RemoveMute(filter, clientId);
    if (ret != SUCCESS) {
        SGLOGE("RemoveMute failed, ret=%{public}d", ret);
        return ret;
    }
    EraseFilterFromSession(clientId, filter);
    return SUCCESS;
}

void AcquireDataSubscribeManager::EraseFilterFromSession(const std::string &clientId,
    const EventMuteFilter &filter)
{
    std::lock_guard<ffrt::mutex> lock(sessionMutex_);
    auto it = sessionsMap_.find(clientId);
    if (it == sessionsMap_.end() || it->second == nullptr) {
        return;
    }
    auto fit = it->second->eventFilters.find(filter.eventId);
    if (fit == it->second->eventFilters.end()) {
        return;
    }
    auto iter = find_if(fit->second.begin(), fit->second.end(),
        [&filter](const EventMuteFilter &item) { return IsSameMuteFilter(filter, item); });
    if (iter != fit->second.end()) {
        fit->second.erase(iter);
        if (fit->second.empty()) {
            it->second->eventFilters.erase(filter.eventId);
        }
    }
}

SecurityCollector::SecurityCollectorEventMuteFilter AcquireDataSubscribeManager::ConvertFilter(
    const SecurityGuard::EventMuteFilter &sgFilter, const std::string &clientId)
{
    SecurityCollector::SecurityCollectorEventMuteFilter collectorFilter {};
    collectorFilter.eventId = sgFilter.eventId;
    collectorFilter.mutes = sgFilter.mutes;
    collectorFilter.type = sgFilter.type;
    collectorFilter.isInclude = sgFilter.isInclude;
    collectorFilter.isSetMute = false;
    collectorFilter.instanceFlag = clientId;
    return collectorFilter;
}

int AcquireDataSubscribeManager::CreatClient(const std::string &eventGroup, const std::string &clientId,
    const sptr<IRemoteObject> &cb)
{
    pid_t callerPid = IPCSkeleton::GetCallingPid();
    int ret = IsExceedLimited(clientId, eventGroup, callerPid);
    if (ret != SUCCESS) {
        SGLOGE("IsExceedLimited error");
        return ret;
    }
    auto session = std::make_shared<ClientSession>();
    session->clientId = clientId;
    session->callback = cb;
    session->pid = callerPid;
    session->eventGroup = eventGroup;
    {
        std::lock_guard<ffrt::mutex> lock(sessionMutex_);
        if (sessionsMap_.find(clientId) != sessionsMap_.end()) {
            SGLOGE("current clientId exist");
            return BAD_PARAM;
        }
        sessionsMap_[clientId] = session;
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::DestoryClient(const std::string &eventGroup, const std::string &clientId)
{
    std::set<int64_t> subEvents {};
    std::vector<EventMuteFilter> filters {};
    {
        std::lock_guard<ffrt::mutex> lock(sessionMutex_);
        auto iter = sessionsMap_.find(clientId);
        if (iter == sessionsMap_.end()) {
            SGLOGE("current clientId not exist");
            return BAD_PARAM;
        }
        subEvents = iter->second->subEvents;
        for (const auto &filterIter : iter->second->eventFilters) {
            for (const auto &filter : filterIter.second) {
                filters.emplace_back(filter);
            }
        }
        sessionsMap_.erase(clientId);
    }
    // 退订与插件删除均在锁外执行
    for (int64_t eventId : subEvents) {
        // 内部重查：仅当无其他会话订阅时才真正退订，避免误停其他订阅者正在使用的采集器
        (void)UnSubscribeScIfLast(eventId);
    }
    for (const auto &filter : filters) {
        (void)RemoveMute(filter, clientId);
    }
    return SUCCESS;
}

int AcquireDataSubscribeManager::IsExceedLimited(
    const std::string &clientId, const std::string &eventGroup, pid_t callerPid)
{
    // old subscribe api no need to count
    if (clientId.find("sdk") != std::string::npos) {
        return SUCCESS;
    }
    std::lock_guard<ffrt::mutex> lock(sessionMutex_);
    size_t auditGroupSessionCount = 0;
    for (auto iter : sessionsMap_) {
        if (iter.second != nullptr && iter.second->eventGroup == eventGroup) {
            ++auditGroupSessionCount;
        }
    }

    if (auditGroupSessionCount >= MAX_SESSION_SIZE) {
        SGLOGE("max instance limited");
        return CLIENT_EXCEED_GLOBAL_LIMIT;
    }
    std::set<std::string> clients {};
    for (auto iter : sessionsMap_) {
        if (iter.second != nullptr && iter.second->pid == callerPid) {
            clients.insert(iter.first);
        }
    }
    if (clients.find(clientId) == clients.end() && clients.size() >= MAX_SESSION_SIZE_ONE_PROCESS) {
        SGLOGE("max instance one process limited");
        return CLIENT_EXCEED_PROCESS_LIMIT;
    }
    return SUCCESS;
}

using RetSessionMap = std::map<std::string, std::shared_ptr<AcquireDataSubscribeManager::ClientSession>>;
RetSessionMap AcquireDataSubscribeManager::GetAuditClientSessionMap()
{
    // 锁内拷贝返回，避免无锁暴露内部容器引用导致的数据竞争
    std::lock_guard<ffrt::mutex> lock(sessionMutex_);
    return sessionsMap_;
}

bool AcquireDataSubscribeManager::HasStickyEventReported(int64_t eventId, const std::string &clientId)
{
    auto it = reportedStickyEvents_.find(clientId);
    if (it == reportedStickyEvents_.end()) {
        return false;
    }
    return it->second.find(eventId) != it->second.end();
}

bool AcquireDataSubscribeManager::MarkStickyEventReported(int64_t eventId, const std::string &clientId)
{
    if (HasStickyEventReported(eventId, clientId)) {
        SGLOGD("sticky event %{public}" PRId64 " has been reported to client %{public}s, skip report",
            eventId, clientId.c_str());
        return false;
    }
    reportedStickyEvents_[clientId].insert(eventId);
    return true;
}
}
