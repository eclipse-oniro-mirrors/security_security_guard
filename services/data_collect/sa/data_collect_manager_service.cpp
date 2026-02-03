/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "data_collect_manager_service.h"
#include <cstdio>
#include <thread>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cinttypes>
#include <fstream>
#include <unistd.h>
#include <unordered_set>
#include "accesstoken_kit.h"
#include "tokenid_kit.h"
#include "ipc_skeleton.h"
#include "string_ex.h"
#include "directory_ex.h"
#include "file_ex.h"
#include "acquire_data_subscribe_manager.h"
#include "bigdata.h"
#include "collector_manager.h"
#include "config_data_manager.h"
#include "data_collect_manager_callback_proxy.h"
#include "data_collect_manager.h"
#include "data_format.h"
#include "sg_collect_client.h"
#include "security_collector_subscriber.h"
#include "security_collector_run_manager.h"
#include "database_manager.h"
#include "data_collection.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "system_ability_definition.h"
#include "ffrt.h"
#include "risk_event_rdb_helper.h"
#include "file_system_store_helper.h"
#include "model_manager.h"
#include "config_define.h"
#include "data_statistics.h"
#include "fdsan_fd.h"
#ifdef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
#include "event_group_config.h"
#endif

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr int32_t TWO_ARGS = 2;
    constexpr int32_t TIMEOUT_REPLY = 10000;
    const std::string REPORT_PERMISSION = "ohos.permission.securityguard.REPORT_SECURITY_INFO";
    const std::string REPORT_PERMISSION_NEW = "ohos.permission.REPORT_SECURITY_EVENT";
    const std::string REQUEST_PERMISSION = "ohos.permission.securityguard.REQUEST_SECURITY_EVENT_INFO";
    const std::string MANAGE_CONFIG_PERMISSION = "ohos.permission.MANAGE_SECURITY_GUARD_CONFIG";
    const std::string QUERY_SECURITY_EVENT_PERMISSION = "ohos.permission.QUERY_SECURITY_EVENT";
    const std::string QUERY_AUDIT_EVENT_PERMISSION = "ohos.permission.QUERY_AUDIT_EVENT";
    constexpr int32_t CFG_FILE_MAX_SIZE = 1 * 1024 * 1024;
    constexpr int32_t CFG_FILE_BUFF_SIZE = 1 * 1024 * 1024 + 1;
    const std::unordered_map<std::string, std::vector<std::string>> g_apiPermissionsMap {
        {"RequestDataSubmit", {REPORT_PERMISSION, REPORT_PERMISSION_NEW}},
        {"QuerySecurityEvent", {REQUEST_PERMISSION, QUERY_SECURITY_EVENT_PERMISSION}},
        {"CollectorStart", {REQUEST_PERMISSION, QUERY_SECURITY_EVENT_PERMISSION}},
        {"CollectorStop", {REQUEST_PERMISSION, QUERY_SECURITY_EVENT_PERMISSION}},
        {"Subscribe", {REQUEST_PERMISSION, QUERY_SECURITY_EVENT_PERMISSION}},
        {"UnSubscribe", {REQUEST_PERMISSION, QUERY_SECURITY_EVENT_PERMISSION}},
        {"ConfigUpdate", {MANAGE_CONFIG_PERMISSION}},
        {"QuerySecurityEventConfig", {MANAGE_CONFIG_PERMISSION}},
        {"AddFilter", {QUERY_SECURITY_EVENT_PERMISSION}},
        {"RemoveFilter", {QUERY_SECURITY_EVENT_PERMISSION}},
        {"QuerySecurityEventById", {QUERY_AUDIT_EVENT_PERMISSION}},
        {"QueryCodeSignInfoByPath", {QUERY_AUDIT_EVENT_PERMISSION}}
    };
    std::mutex g_configCacheMutex;
    std::unordered_set<std::string> g_configCacheFilesSet;
    constexpr uint32_t FINISH = 0;
    constexpr uint32_t CONTINUE = 1;
    constexpr size_t MAX_DISTRIBUTE_LENS = 100;
    std::string TRUST_LIST_FILE_PATH_PRE = "/system/etc/";
    const std::string TRUST_LIST_FILE_PATH = TRUST_LIST_FILE_PATH_PRE + SECURITY_GUARD_CONFIG_UPDATE_TRUST_LIST_SOURCE;
    constexpr int32_t TOKEN_BUCKET_MAX_SIZE = 12000;
    constexpr int32_t TOKEN_BUCKET_STEP_SIZE = 20;
    constexpr int32_t TOKEN_BUCKET_INTERVAL_TIME = 1000;
}

REGISTER_SYSTEM_ABILITY_BY_ID(DataCollectManagerService, DATA_COLLECT_MANAGER_SA_ID, true);

DataCollectManagerService::DataCollectManagerService(int32_t saId, bool runOnCreate)
    : SystemAbility(saId, runOnCreate)
{
    SGLOGW("%{public}s", __func__);
}

typedef void (*InitAllConfigFunc)();
typedef bool (*UpdateConfigFunc)(const std::string &);

void DataCollectManagerService::OnStart()
{
    SGLOGI("%{public}s", __func__);
    DatabaseManager::GetInstance().Init(); // Make sure the database is ready

    void *handle = dlopen("libsg_config_manager.z.so", RTLD_LAZY);
    if (handle == nullptr) {
        SGLOGE("dlopen error: %{public}s", dlerror());
    } else {
        auto func = (InitAllConfigFunc)dlsym(handle, "InitAllConfig");
        if (func != nullptr) {
            SGLOGI("begin init all config");
            func();
        } else {
            SGLOGE("dlsym error: %{public}s", dlerror());
        }
        dlclose(handle);
    }
    AcquireDataSubscribeManager::GetInstance().InitEventQueue();
    AcquireDataSubscribeManager::GetInstance().SubscriberEventOnSgStart();
    AcquireDataSubscribeManager::GetInstance().StartTokenBucketTask();
    if (!Publish(this)) {
        SGLOGE("Publish error");
        return;
    }
    AcquireDataSubscribeManager::GetInstance().StartClearEventCache();
    auto tokenBucketTask = [this]() {
        while (true) {
            if (tokenBucket_.load() < TOKEN_BUCKET_MAX_SIZE) {
                tokenBucket_.fetch_add(TOKEN_BUCKET_STEP_SIZE);
            }
            ffrt::this_task::sleep_for(std::chrono::milliseconds(TOKEN_BUCKET_INTERVAL_TIME));
        }
    };
    ffrt::submit(tokenBucketTask);
}

void DataCollectManagerService::OnStop()
{
    SecurityCollector::DataCollection::GetInstance().CloseLib();
    AcquireDataSubscribeManager::GetInstance().StopClearEventCache();
    AcquireDataSubscribeManager::GetInstance().DeInitDeviceId();
    AcquireDataSubscribeManager::GetInstance().DeInitEventQueue();
    AcquireDataSubscribeManager::GetInstance().StopTokenBucketTask();
}

int DataCollectManagerService::Dump(int fd, const std::vector<std::u16string>& args)
{
    SGLOGI("DataCollectManagerService Dump");
    if (fd < 0) {
        return BAD_PARAM;
    }

    std::string arg0 = ((args.size() == 0) ? "" : Str16ToStr8(args.at(0)));
    if (arg0.compare("-h") == 0) {
        dprintf(fd, "Usage:\n");
        dprintf(fd, "       -h: command help\n");
        dprintf(fd, "       -i <EVENT_ID>: dump special eventId\n");
    } else if (arg0.compare("-i") == 0) {
        if (args.size() < TWO_ARGS) {
            return BAD_PARAM;
        }

        int64_t eventId;
        bool isSuccess = SecurityGuardUtils::StrToI64(Str16ToStr8(args.at(1)), eventId);
        if (!isSuccess) {
            return BAD_PARAM;
        }

        DumpEventInfo(fd, eventId);
    }
    return ERR_OK;
}

void DataCollectManagerService::DumpEventInfo(int fd, int64_t eventId)
{
    SecEvent secEvent;
    int code = DatabaseManager::GetInstance().QueryRecentEventByEventId(eventId, secEvent);
    if (code != SUCCESS) {
        SGLOGE("query event error, code=%{public}d", code);
        return;
    }
    dprintf(fd, "eventId : %ld\n", secEvent.eventId);
    dprintf(fd, "report time : %s\n", secEvent.date.c_str());
    dprintf(fd, "report version : %s\n", secEvent.version.c_str());
}

ErrCode DataCollectManagerService::RequestDataSubmit(int64_t eventId, const std::string &version,
    const std::string &time, const std::string &content)
{
    if (tokenBucket_.load() <= 0) {
        DataStatistics::GetInstance().IncrementRequestDataSubmit();
        return FAILED;
    }
    tokenBucket_.fetch_sub(1);
    SGLOGD("enter DataCollectManagerService RequestDataSubmit");
    int32_t ret = IsApiHasPermission("RequestDataSubmit");
    if (ret != SUCCESS) {
        return ret;
    }
    SecurityCollector::Event event {};
    event.eventId = eventId;
    event.version = version;
    event.timestamp = time;
    event.content = content;
    return AcquireDataSubscribeManager::GetInstance().UploadEvent(event);
}

ErrCode DataCollectManagerService::RequestDataSubmitAsync(int64_t eventId, const std::string &version,
    const std::string &time, const std::string &content)
{
    SGLOGD("enter DataCollectManagerService RequestDataSubmitAsync");
    return RequestDataSubmit(eventId, version, time, content);
}

ErrCode DataCollectManagerService::RequestRiskData(const std::string &devId, const std::string &eventList,
    const sptr<IRemoteObject> &cb)
{
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int code = AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, REQUEST_PERMISSION);
    if (code != AccessToken::PermissionState::PERMISSION_GRANTED) {
        SGLOGE("caller no permission");
        return NO_PERMISSION;
    }
    AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenType(callerToken);
    if (tokenType != AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
        if (!AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)) {
            SGLOGE("not system app no permission");
            return NO_SYSTEMCALL;
        }
    }
    ObtainDataEvent event;
    auto pid = IPCSkeleton::GetCallingPid();
    event.pid = pid;
    event.time = SecurityGuardUtils::GetDate();
    SGLOGI("eventList=%{public}s", eventList.c_str());
    auto promise = std::make_shared<std::promise<int32_t>>();
    auto future = promise->get_future();
    PushDataCollectTask(cb, eventList, devId, promise);
    std::chrono::milliseconds span(TIMEOUT_REPLY);
    if (future.wait_for(span) == std::future_status::timeout) {
        SGLOGE("wait for result timeout");
        event.size = 0;
    } else {
        event.size = future.get();
    }
    SGLOGI("ReportObtainDataEvent");
    BigData::ReportObtainDataEvent(event);
    return SUCCESS;
}

std::vector<SecEvent> DataCollectManagerService::GetSecEventsFromConditions(RequestCondition &condition)
{
    std::vector<SecEvent> events {};
    if (condition.beginTime.empty() && condition.endTime.empty()) {
        (void) DatabaseManager::GetInstance().QueryEventByEventId(RISK_TABLE, condition.riskEvent, events);
    } else {
        (void) DatabaseManager::GetInstance().QueryEventByEventIdAndDate(RISK_TABLE, condition.riskEvent, events,
            condition.beginTime, condition.endTime);
    }
    return events;
}

void to_json(nlohmann::json &jsonObj, const SecEvent &eventDataSt)
{
    jsonObj = nlohmann::json {
        { "eventId", eventDataSt.eventId },
        { "version", eventDataSt.version },
        { "date", eventDataSt.date },
        { "content", eventDataSt.content },
        { "userId", eventDataSt.userId },
        { "deviceId", eventDataSt.deviceId },
    };
}

void DataCollectManagerService::PushDataCollectTask(const sptr<IRemoteObject> &object,
    std::string conditions, std::string devId, std::shared_ptr<std::promise<int32_t>> promise)
{
    auto task = [object, conditions, devId, promise] () mutable {
        auto proxy = iface_cast<IDataCollectManagerCallback>(object);
        if (proxy == nullptr) {
            promise->set_value(0);
            return;
        }
        RequestCondition reqCondition {};
        DataFormat::ParseConditions(conditions, reqCondition);
        if (reqCondition.riskEvent.empty() && reqCondition.auditEvent.empty()) {
            SGLOGE("reqCondition no permission");
            std::string empty;
            proxy->ResponseRiskData(devId, empty, FINISH);
            promise->set_value(0);
            return;
        }

        std::vector<SecEvent> events = GetSecEventsFromConditions(reqCondition);
        size_t curIndex = 0;
        size_t lastIndex = curIndex + MAX_DISTRIBUTE_LENS;
        size_t maxIndex = events.size();
        promise->set_value(maxIndex);
        SGLOGI("events size=%{public}zu", maxIndex);
        std::vector<SecEvent> dispatchVec;
        while (lastIndex < maxIndex) {
            dispatchVec.assign(events.begin() + curIndex, events.begin() + lastIndex);
            std::string dispatch = nlohmann::json(dispatchVec).dump();
            SGLOGD("dispatch size=%{public}zu", dispatch.size());
            (void) proxy->ResponseRiskData(devId, dispatch, CONTINUE);
            curIndex = lastIndex;
            lastIndex = curIndex + MAX_DISTRIBUTE_LENS;
        }

        // last dispatch
        dispatchVec.assign(events.begin() + curIndex, events.end());
        std::string dispatch = nlohmann::json(dispatchVec).dump();
        (void) proxy->ResponseRiskData(devId, dispatch, FINISH);
        SGLOGI("ResponseRiskData FINISH");
    };
    ffrt::submit(task);
}

void DataCollectManagerService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    SGLOGI("OnAddSystemAbility, systemAbilityId=%{public}d", systemAbilityId);
}

void DataCollectManagerService::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    SGLOGW("OnRemoveSystemAbility, systemAbilityId=%{public}d", systemAbilityId);
}

ErrCode DataCollectManagerService::Subscribe(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &cb, const std::string &clientId)
{
    SGLOGD("DataCollectManagerService, start subscribe");
    int32_t ret = FAILED;
    SgSubscribeEvent event;
    event.pid = IPCSkeleton::GetCallingPid();
    event.time = SecurityGuardUtils::GetDate();
    event.eventId = subscribeInfo.GetEvent().eventId;
    if (subscribeInfo.GetEventGroup() == "") {
        ret = IsApiHasPermission("Subscribe");
    } else if (subscribeInfo.GetEventGroup() == "auditGroup") {
        ret = IsEventGroupHasPublicPermission(subscribeInfo.GetEventGroup(), {});
    } else {
        ret = IsEventGroupHasPermission(subscribeInfo.GetEventGroup(),
            std::vector<int64_t>{subscribeInfo.GetEvent().eventId});
    }
    if (ret != SUCCESS) {
        event.ret = ret;
        BigData::ReportSgSubscribeEvent(event);
        return ret;
    }
    ret = SetDeathCallBack(event, cb);
    if (ret != SUCCESS) {
        return ret;
    }
    ret = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, cb, clientId);
    event.ret = ret;
    SGLOGI("DataCollectManagerService, InsertSubscribeRecord eventId=%{public}" PRId64, event.eventId);
    BigData::ReportSgSubscribeEvent(event);
    return ret;
}

ErrCode DataCollectManagerService::Unsubscribe(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &cb, const std::string &clientId)
{
    int32_t ret = FAILED;
    SgUnsubscribeEvent event;
    event.pid = IPCSkeleton::GetCallingPid();
    event.time = SecurityGuardUtils::GetDate();
    if (subscribeInfo.GetEventGroup() == "") {
        ret = IsApiHasPermission("UnSubscribe");
    } else if (subscribeInfo.GetEventGroup() == "auditGroup") {
        ret = IsEventGroupHasPublicPermission(subscribeInfo.GetEventGroup(), {});
    } else {
        ret = IsEventGroupHasPermission(subscribeInfo.GetEventGroup(),
            std::vector<int64_t>{subscribeInfo.GetEvent().eventId});
    }
    if (ret != SUCCESS) {
        event.ret = ret;
        BigData::ReportSgUnsubscribeEvent(event);
        return ret;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (deathRecipient_ != nullptr) {
            cb->RemoveDeathRecipient(deathRecipient_);
        }
    }
    ret = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(subscribeInfo.GetEvent().eventId, cb,
        clientId);
    event.ret = ret;
    SGLOGI("DataCollectManagerService, RemoveSubscribeRecord ret=%{public}d", ret);
    BigData::ReportSgUnsubscribeEvent(event);
    return ret;
}

void DataCollectManagerService::QuerySecurityEventCallBack(sptr<ISecurityEventQueryCallback> proxy,
    std::vector<SecurityCollector::SecurityEvent> events)
{
    int32_t step = MAX_ON_QUERY_SIZE;
    if (events.size() > 0 && events.size() <= static_cast<size_t>(MAX_ON_QUERY_SIZE)) {
        proxy->OnQuery(events);
    } else if (events.size() > static_cast<size_t>(MAX_ON_QUERY_SIZE)) {
        std::vector<SecurityCollector::SecurityEvent>::iterator curPtr = events.begin();
        std::vector<SecurityCollector::SecurityEvent>::iterator endPtr = events.end();
        std::vector<SecurityCollector::SecurityEvent>::iterator end;
        while (curPtr < endPtr) {
            end = endPtr - curPtr > step ? step + curPtr : endPtr;
            step = endPtr - curPtr > step ? step : endPtr - curPtr;
            proxy->OnQuery(std::vector<SecurityCollector::SecurityEvent>(curPtr, end));
            curPtr += step;
        }
    }
}

bool DataCollectManagerService::QueryEventByRuler(sptr<ISecurityEventQueryCallback> proxy,
    SecurityCollector::SecurityEventRuler ruler)
{
    EventCfg config;
    bool isSuccess = ConfigDataManager::GetInstance().GetEventConfig(ruler.GetEventId(), config);
    if (!isSuccess) {
        SGLOGE("GetEventConfig error, eventId is 0x%{public}" PRIx64, ruler.GetEventId());
        return false;
    }
    std::vector<SecurityCollector::SecurityEvent> replyEvents;
    std::vector<int64_t> eventIds{ruler.GetEventId()};
    SGLOGD("eventType is %{public}u", config.eventType);
    if (config.eventType == 1) { // query in collector
        int32_t code = FAILED;
        if (config.prog == "security_guard") {
            code = SecurityCollector::DataCollection::GetInstance().QuerySecurityEvent({ruler}, replyEvents);
        } else {
            code = SecurityCollector::CollectorManager::GetInstance().QuerySecurityEvent(
                {ruler}, replyEvents);
        }
        if (code != SUCCESS) {
            return false;
        }
        QuerySecurityEventCallBack(proxy, replyEvents);
    } else { // query in db
        if (config.dbTable == FILE_SYSTEM) {
            (void) FileSystemStoreHelper::GetInstance().QuerySecurityEvent(ruler, proxy);
            return true;
        }
        std::vector<SecEvent> events;
        if (ruler.GetBeginTime().empty() && ruler.GetEndTime().empty()) {
            (void) DatabaseManager::GetInstance().QueryEventByEventId(ruler.GetEventId(), events);
        } else {
            (void) DatabaseManager::GetInstance().QueryEventByEventIdAndDate(RISK_TABLE, eventIds, events,
                ruler.GetBeginTime(), ruler.GetEndTime());
        }
        std::transform(events.begin(), events.end(),
            std::back_inserter(replyEvents), [] (SecEvent event) {
            return SecurityCollector::SecurityEvent(event.eventId, event.version, event.content, event.date);
        });
        QuerySecurityEventCallBack(proxy, replyEvents);
    }
    return true;
}

ErrCode DataCollectManagerService::QuerySecurityEventById(const std::vector<SecurityCollector::SecurityEventRuler>
    &rulers, const sptr<IRemoteObject> &cb, const std::string &eventGroup)
{
    SGLOGI("enter DataCollectManagerService QuerySecurityEventById");
    int32_t ret = IsEventGroupHasPublicPermission(eventGroup, std::vector<int64_t>{});
    if (ret != SUCCESS) {
        return ret;
    }
    auto proxy = iface_cast<ISecurityEventQueryCallback>(cb);
    if (proxy == nullptr) {
        SGLOGI("proxy is null");
        return NULL_OBJECT;
    }
    const int64_t queryPorcInfoEventId = 1011015023;
    std::unordered_set<int64_t> eventIds = {queryPorcInfoEventId};
    auto task = [proxy, rulers, eventIds] {
        std::string errEventIds;
        for (auto &ruler : rulers) {
            if (eventIds.count(ruler.GetEventId()) == 0) {
                SGLOGE("eventid not in eventid list eventId=%{public}" PRId64, ruler.GetEventId());
                errEventIds.append(std::to_string(ruler.GetEventId()) + " ");
                continue;
            }
            if (!QueryEventByRuler(proxy, ruler)) {
                errEventIds.append(std::to_string(ruler.GetEventId()) + " ");
            }
        }
        if (!errEventIds.empty()) {
            std::string message = "QuerySecurityEvent " + errEventIds + "failed";
            SGLOGE("QuerySecurityEvent failed");
            proxy->OnError(message);
            return;
        }
        proxy->OnComplete();
    };
    ffrt::submit(task);
    return SUCCESS;
}

ErrCode DataCollectManagerService::QuerySecurityEvent(const std::vector<SecurityCollector::SecurityEventRuler> &rulers,
    const sptr<IRemoteObject> &cb, const std::string &eventGroup)
{
    SGLOGI("enter DataCollectManagerService QuerySecurityEvent");
    int32_t ret = 0;
    if (eventGroup == "") {
        ret = IsApiHasPermission("QuerySecurityEvent");
    } else {
        ret = IsEventGroupHasPermission(eventGroup, std::vector<int64_t>{});
    }
    if (ret != SUCCESS) {
        return ret;
    }
    auto proxy = iface_cast<ISecurityEventQueryCallback>(cb);
    if (proxy == nullptr) {
        SGLOGI("proxy is null");
        return NULL_OBJECT;
    }
    auto task = [proxy, rulers, eventGroup] {
        std::string errEventIds;
        EventGroupCfg config {};
        if (!ConfigDataManager::GetInstance().GetEventGroupConfig(eventGroup, config)) {
            SGLOGE("get event group config fail group = %{public}s", eventGroup.c_str());
            return;
        }
        for (auto &ruler : rulers) {
            if (config.eventList.count(ruler.GetEventId()) == 0) {
                SGLOGE("eventid not in eventid list");
                errEventIds.append(std::to_string(ruler.GetEventId()) + " ");
                continue;
            }
            if (!QueryEventByRuler(proxy, ruler)) {
                errEventIds.append(std::to_string(ruler.GetEventId()) + " ");
            }
        }
        if (!errEventIds.empty()) {
            std::string message = "QuerySecurityEvent " + errEventIds + "failed";
            SGLOGE("QuerySecurityEvent failed");
            proxy->OnError(message);
            return;
        }
        proxy->OnComplete();
    };
    ffrt::submit(task);
    return SUCCESS;
}

void DataCollectManagerService::SubscriberDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    SGLOGI("enter OnRemoteDied");
    if (remote == nullptr) {
        SGLOGE("remote object is nullptr");
        return;
    }

    sptr<IRemoteObject> object = remote.promote();
    if (object == nullptr) {
        SGLOGE("object is nullptr");
        return;
    }
    sptr<DataCollectManagerService> service = service_.promote();
    if (service == nullptr) {
        SGLOGE("service is nullptr");
        return;
    }
    AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecordOnRemoteDied(object);
    if (object->IsProxyObject() && service->deathRecipient_ != nullptr) {
        object->RemoveDeathRecipient(service->deathRecipient_);
    }
    SGLOGI("end OnRemoteDied");
}

ErrCode DataCollectManagerService::CollectorStart(
    const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &cb)
{
    SGLOGI("enter DataCollectManagerService CollectorStart.");
    int32_t code = IsApiHasPermission("CollectorStart");
    if (code != SUCCESS) {
        return code;
    }
    EventCfg config;
    if (!ConfigDataManager::GetInstance().GetEventConfig(subscribeInfo.GetEvent().eventId, config)) {
        SGLOGE("GetEventConfig error, eventId is 0x%{public}" PRIx64, subscribeInfo.GetEvent().eventId);
        return BAD_PARAM;
    }
    auto eventHandler = [this] (const std::string &appName, const sptr<IRemoteObject> &remote,
        const SecurityCollector::Event &event) {
        SGLOGD("eventid:%{public}" PRId64 " callback default", event.eventId);
        auto reportEvent = [event] () {
            auto info = std::make_shared<SecurityGuard::EventInfo>(event.eventId, event.version, event.content);
            SecurityGuard::NativeDataCollectKit::ReportSecurityInfo(info);
        };
        reportEvent();
        return;
    };
    if (config.prog == "security_guard") {
        auto subscriber = std::make_shared<SecurityCollector::SecurityCollectorSubscriber>("security_guard",
            subscribeInfo, nullptr, eventHandler);
        if (!SecurityCollector::SecurityCollectorRunManager::GetInstance().StartCollector(subscriber)) {
            return BAD_PARAM;
        }
        return SUCCESS;
    } else {
        code = SecurityCollector::CollectorManager::GetInstance().CollectorStart(subscribeInfo);
        if (code != SUCCESS) {
            SGLOGI("CollectorStart failed, code=%{public}d", code);
            return code;
        }
    }
    return SUCCESS;
}

ErrCode DataCollectManagerService::CollectorStop(const SecurityCollector::SecurityCollectorSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &cb)
{
    SGLOGI("enter DataCollectManagerService CollectorStop.");
    int32_t code = IsApiHasPermission("CollectorStop");
    if (code != SUCCESS) {
        return code;
    }
    EventCfg config;
    if (!ConfigDataManager::GetInstance().GetEventConfig(subscribeInfo.GetEvent().eventId, config)) {
        SGLOGE("GetEventConfig error, eventId is 0x%{public}" PRIx64, subscribeInfo.GetEvent().eventId);
        return BAD_PARAM;
    }
    auto eventHandler = [this] (const std::string &appName, const sptr<IRemoteObject> &remote,
        const SecurityCollector::Event &event) {
        return;
    };
    if (config.prog == "security_guard") {
        auto subscriber = std::make_shared<SecurityCollector::SecurityCollectorSubscriber>("security_guard",
            subscribeInfo, nullptr, eventHandler);
        if (!SecurityCollector::SecurityCollectorRunManager::GetInstance().StopCollector(subscriber)) {
            return BAD_PARAM;
        }
        return SUCCESS;
    } else {
        code = SecurityCollector::CollectorManager::GetInstance().CollectorStop(subscribeInfo);
        if (code != SUCCESS) {
            SGLOGI("CollectorStop failed, code=%{public}d", code);
            return code;
        }
    }
    return SUCCESS;
}

int32_t DataCollectManagerService::IsApiHasPermission(const std::string &api)
{
    if (g_apiPermissionsMap.count(api) == 0) {
        SGLOGE("api not in map");
        return FAILED;
    }
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    if (std::any_of(g_apiPermissionsMap.at(api).cbegin(), g_apiPermissionsMap.at(api).cend(),
        [callerToken](const std::string &per) {
        int code = AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, per);
        return code == AccessToken::PermissionState::PERMISSION_GRANTED;
    })) {
        AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenType(callerToken);
        if (tokenType != AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
            uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
            if (!AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)) {
                SGLOGE("not system app no permission");
                return NO_SYSTEMCALL;
            }
        }
        return SUCCESS;
    }
    SGLOGE("caller no permission");
    return NO_PERMISSION;
}

int32_t DataCollectManagerService::IsEventGroupHasPublicPermission(const std::string &eventGroup,
    std::vector<int64_t> eventIds)
{
    EventGroupCfg config {};
    if (!ConfigDataManager::GetInstance().GetEventGroupConfig(eventGroup, config)) {
        SGLOGE("get event group config fail group = %{public}s", eventGroup.c_str());
        return BAD_PARAM;
    }
    for (int64_t eventId : eventIds) {
        if (config.eventList.count(eventId) == 0) {
            SGLOGE("eventid not in eventid list");
            return BAD_PARAM;
        }
    }
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    if (std::any_of(config.permissionList.cbegin(), config.permissionList.cend(),
        [callerToken](const std::string &per) {
        int code = AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, per);
        return code == AccessToken::PermissionState::PERMISSION_GRANTED;
    })) {
        return SUCCESS;
    }
    SGLOGE("caller no permission");
    return NO_PERMISSION;
}

int32_t DataCollectManagerService::IsEventGroupHasPermission(const std::string &eventGroup,
    std::vector<int64_t> eventIds)
{
    EventGroupCfg config {};
    if (!ConfigDataManager::GetInstance().GetEventGroupConfig(eventGroup, config)) {
        SGLOGE("get event group config fail group = %{public}s", eventGroup.c_str());
        return BAD_PARAM;
    }
    for (int64_t eventId : eventIds) {
        if (config.eventList.count(eventId) == 0) {
            SGLOGE("eventid not in eventid list");
            return BAD_PARAM;
        }
    }
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    if (std::any_of(config.permissionList.cbegin(), config.permissionList.cend(),
        [callerToken](const std::string &per) {
        int code = AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, per);
        return code == AccessToken::PermissionState::PERMISSION_GRANTED;
    })) {
        AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenType(callerToken);
        if (tokenType != AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
            uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
            if (!AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)) {
                SGLOGE("not system app no permission");
                return NO_SYSTEMCALL;
            }
        }
        return SUCCESS;
    }
    SGLOGE("caller no permission");
    return NO_PERMISSION;
}

int32_t DataCollectManagerService::WriteRemoteFileToLocal(int fd, const std::string &realPath)
{
    FdsanFd currentFd(fd);
    FdsanFd outputFd(dup(currentFd.Get()));
    currentFd.Reset();
    if (outputFd.Get() < 0) {
        SGLOGE("dup fd fail reason %{public}s", strerror(errno));
        return FAILED;
    }
    FdsanFd inputFd(open(realPath.c_str(), O_WRONLY | O_NOFOLLOW | O_CLOEXEC | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR));
    if (inputFd.Get() < 0) {
        outputFd.Reset();
        SGLOGE("open file fail reason %{public}s", strerror(errno));
        return FAILED;
    }
    auto buffer = std::make_unique<char[]> (CFG_FILE_BUFF_SIZE);
    int offset = -1;
    while ((offset = read(outputFd.Get(), buffer.get(), CFG_FILE_BUFF_SIZE)) > 0) {
        if (offset > CFG_FILE_MAX_SIZE) {
            outputFd.Reset();
            inputFd.Reset();
            SGLOGE("file is empty or too large, len = %{public}d", offset);
            return BAD_PARAM;
        }
        if (write(inputFd.Get(), buffer.get(), offset) < 0) {
            inputFd.Reset();
            outputFd.Reset();
            SGLOGE("write file to the tmp dir failed");
            return FAILED;
        }
    }
    inputFd.Reset();
    fsync(outputFd.Get());
    outputFd.Reset();
    return SUCCESS;
}

bool DataCollectManagerService::ParseTrustListFile(const std::string &trustListFile)
{
    if (trustListFile.empty()) {
        SGLOGE("path is empty");
        return false;
    }
    std::ifstream stream(trustListFile, std::ios::in);
    if (!stream.is_open()) {
        SGLOGE("stream error");
        return false;
    }
    stream.seekg(0, std::ios::end);
    std::ios::pos_type cfgFileMaxSize = 1 * 1024 * 1024;
    std::ios::pos_type len = stream.tellg();
    if (len == 0 || len > cfgFileMaxSize) {
        SGLOGE("stream is empty or too large");
        stream.close();
        return false;
    }
    stream.seekg(0, std::ios_base::beg);
    nlohmann::json jsonObj = nlohmann::json::parse(stream, nullptr, false);
    stream.close();
    if (jsonObj.is_discarded()) {
        SGLOGE("json is discarded");
        return false;
    }

    if (!jsonObj.contains("trust_list_config") || !jsonObj["trust_list_config"].is_array()) {
        return false;
    }

    for (const auto &ele : jsonObj["trust_list_config"]) {
        if (!ele.contains("name")) {
            return false;
        }
        g_configCacheFilesSet.emplace(ele["name"]);
    }

    return true;
}

ErrCode DataCollectManagerService::ConfigUpdate(int fd, const std::string& name)
{
    SGLOGI("enter DataCollectManagerService ConfigUpdate.");
    int32_t code = IsApiHasPermission("ConfigUpdate");
    if (code != SUCCESS) {
        return code;
    }
    {
        std::lock_guard<std::mutex> lock(g_configCacheMutex);
        if (!ParseTrustListFile(TRUST_LIST_FILE_PATH)) {
            return BAD_PARAM;
        }
        if (g_configCacheFilesSet.empty() || !g_configCacheFilesSet.count(name)) {
            return BAD_PARAM;
        }
    }
    
    const std::string &realPath = CONFIG_ROOT_PATH + "tmp/" + name;
    SGLOGI("config file is %{public}s, fd is %{public}d", realPath.c_str(), fd);
    std::string tmpPath = realPath + ".t";
    int32_t ret = WriteRemoteFileToLocal(fd, tmpPath);
    if (ret != SUCCESS) {
        SGLOGE("write remote file to local fail");
        return ret;
    }
    if (rename(tmpPath.c_str(), realPath.c_str()) != 0) {
        SGLOGE("remote file rename fail");
        (void)unlink(tmpPath.c_str());
        return FAILED;
    }
    (void)unlink(tmpPath.c_str());
    void *handle = dlopen("libsg_config_manager.z.so", RTLD_LAZY);
    if (handle == nullptr) {
        SGLOGE("dlopen error: %{public}s", dlerror());
        return FAILED;
    }
    auto func = (UpdateConfigFunc)dlsym(handle, "UpdateConfig");
    if (func == nullptr) {
        SGLOGE("dlsym error: %{public}s", dlerror());
        dlclose(handle);
        return FAILED;
    }
    if (!func(realPath)) {
        SGLOGE("update config fail");
        dlclose(handle);
        return FAILED;
    }
    dlclose(handle);
    return SUCCESS;
}

int32_t DataCollectManagerService::QueryEventConfig(std::string &result)
{
    SGLOGI("Start DataCollectManagerService::QueryEventConfig");
    std::vector<EventCfg> eventConfigs = ConfigDataManager::GetInstance().GetAllEventConfigs();
    nlohmann::json resultObj = nlohmann::json::array();
    for (const auto& event : eventConfigs) {
        nlohmann::json jObject;
        jObject["eventId"] = event.eventId;
        jObject["eventName"] = event.eventName;
        jObject["version"] = event.version;
        jObject["eventType"] = event.eventType;
        jObject["collectOnStart"] = event.collectOnStart;
        jObject["dataSensitivityLevel"] = event.dataSensitivityLevel;
        jObject["discardEventWhiteList"] = event.discardEventWhiteList;
        jObject["storageRamNums"] = event.storageRamNums;
        jObject["storageRomNums"] = event.storageRomNums;
        jObject["storageTime"] = event.storageTime;
        jObject["owner"] = event.owner;
        jObject["source"] = event.source;
        jObject["dbTable"] = event.dbTable;
        jObject["prog"] = event.prog;
        jObject["isBatchUpload"] = event.isBatchUpload;
        resultObj.push_back(jObject);
    }
    result = resultObj.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    return SUCCESS;
}

ErrCode DataCollectManagerService::QuerySecurityEventConfig(std::string &result)
{
    SGLOGI("enter QuerySecurityEventConfig");
    int32_t ret = IsApiHasPermission("QuerySecurityEventConfig");
    if (ret != SUCCESS) {
        return ret;
    }
    return QueryEventConfig(result);
}

ErrCode DataCollectManagerService::AddFilter(const SecurityEventFilter &subscribeMute, const std::string &clientId)
{
    SGLOGI("enter DataCollectManagerService AddFilter.");
    int32_t ret = FAILED;
    SgSubscribeEvent event;
    EventMuteFilter filter = subscribeMute.GetMuteFilter();
    event.pid = IPCSkeleton::GetCallingPid();
    event.time = SecurityGuardUtils::GetDate();
    event.eventId = filter.eventId;
    std::string eventGroup = AcquireDataSubscribeManager::GetInstance().GetCurrentClientGroup(clientId);
    if (eventGroup == "securityGroup") {
        ret = IsEventGroupHasPermission(eventGroup, std::vector<int64_t>{filter.eventId});
    } else {
        ret = IsEventGroupHasPublicPermission(eventGroup, std::vector<int64_t>{filter.eventId});
    }
    if (ret != SUCCESS) {
        event.ret = ret;
        BigData::ReportSetMuteEvent(event);
        return ret;
    }
    ret = AcquireDataSubscribeManager::GetInstance().InsertSubscribeMute(filter, clientId);
    if (ret != SUCCESS) {
        SGLOGE("InsertSubscribeMute fail");
        event.ret = ret;
        BigData::ReportSetMuteEvent(event);
        return ret;
    }
    event.ret = ret;
    BigData::ReportSetMuteEvent(event);
    return ret;
}

ErrCode DataCollectManagerService::RemoveFilter(const SecurityEventFilter &subscribeMute, const std::string &clientId)
{
    SGLOGI("enter DataCollectManagerService RemoveFilter.");
    SgSubscribeEvent event;
    EventMuteFilter filter = subscribeMute.GetMuteFilter();
    event.pid = IPCSkeleton::GetCallingPid();
    event.time = SecurityGuardUtils::GetDate();
    event.eventId = filter.eventId;
    std::string eventGroup = AcquireDataSubscribeManager::GetInstance().GetCurrentClientGroup(clientId);
    int32_t ret = 0;
    if (eventGroup == "securityGroup") {
        ret = IsEventGroupHasPermission(eventGroup, std::vector<int64_t>{filter.eventId});
    } else {
        ret = IsEventGroupHasPublicPermission(eventGroup, std::vector<int64_t>{filter.eventId});
    }
    if (ret != SUCCESS) {
        event.ret = ret;
        BigData::ReportSetUnMuteEvent(event);
        return ret;
    }
    ret = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeMute(filter, clientId);
    if (ret != SUCCESS) {
        SGLOGE("fail to RemoveSubscribeMute");
        event.ret = ret;
        BigData::ReportSetUnMuteEvent(event);
        return ret;
    }
    event.ret = ret;
    BigData::ReportSetUnMuteEvent(event);
    return ret;
}

int32_t DataCollectManagerService::SetDeathCallBack(SgSubscribeEvent event, const sptr<IRemoteObject> &callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (deathRecipient_ == nullptr) {
        deathRecipient_ = new (std::nothrow) SubscriberDeathRecipient(this);
        if (deathRecipient_ == nullptr) {
            SGLOGE("no memory");
            event.ret = NULL_OBJECT;
            BigData::ReportSgSubscribeEvent(event);
            return NULL_OBJECT;
        }
    }
    callback->AddDeathRecipient(deathRecipient_);
    return SUCCESS;
}

ErrCode DataCollectManagerService::Subscribe(int64_t eventId, const std::string &clientId)
{
    SGLOGI("DataCollectManagerService, start new subscribe");
    int32_t ret = FAILED;
    SgSubscribeEvent event;
    event.pid = IPCSkeleton::GetCallingPid();
    event.time = SecurityGuardUtils::GetDate();
    event.eventId = eventId;
    std::string eventGroup = AcquireDataSubscribeManager::GetInstance().GetCurrentClientGroup(clientId);
    if (eventGroup == "securityGroup") {
        ret = IsEventGroupHasPermission(eventGroup, {});
    } else {
        ret = IsEventGroupHasPublicPermission(eventGroup, {});
    }
    if (ret != SUCCESS) {
        event.ret = ret;
        BigData::ReportSgSubscribeEvent(event);
        return ret;
    }
    ret = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(eventId, clientId);
    if (ret != SUCCESS) {
        SGLOGE("InsertSubscribeRecord fail");
        event.ret = ret;
        BigData::ReportSgSubscribeEvent(event);
        return ret;
    }
    event.ret = ret;
    SGLOGI("DataCollectManagerService, InsertSubscribeRecord eventId=%{public}" PRId64, event.eventId);
    BigData::ReportSgSubscribeEvent(event);
    return SUCCESS;
}

ErrCode DataCollectManagerService::Unsubscribe(int64_t eventId, const std::string &clientId)
{
    SGLOGI("DataCollectManagerService, start new Unsubscribe");
    int32_t ret = FAILED;
    SgUnsubscribeEvent event;
    event.pid = IPCSkeleton::GetCallingPid();
    event.time = SecurityGuardUtils::GetDate();
    std::string eventGroup = AcquireDataSubscribeManager::GetInstance().GetCurrentClientGroup(clientId);
    if (eventGroup == "securityGroup") {
        ret = IsEventGroupHasPermission(eventGroup, {});
    } else {
        ret = IsEventGroupHasPublicPermission(eventGroup, {});
    }
    if (ret != SUCCESS) {
        event.ret = ret;
        BigData::ReportSgUnsubscribeEvent(event);
        return ret;
    }
    ret = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(eventId, clientId);
    if (ret != SUCCESS) {
        SGLOGE("RemoveSubscribeRecord fail");
        event.ret = ret;
        BigData::ReportSgUnsubscribeEvent(event);
        return ret;
    }
    event.ret = ret;
    SGLOGI("DataCollectManagerService, RemoveSubscribeRecord ret=%{public}d", ret);
    BigData::ReportSgUnsubscribeEvent(event);
    return ret;
}

ErrCode DataCollectManagerService::DestoryClient(const std::string &eventGroup, const std::string &clientId)
{
    SGLOGI("DataCollectManagerService, DestoryClient");
    if (eventGroup == "") {
        SGLOGE("event group empty");
        return BAD_PARAM;
    }
    int32_t ret = 0;
    if (eventGroup == "securityGroup") {
        ret = IsEventGroupHasPermission(eventGroup, {});
    } else {
        ret = IsEventGroupHasPublicPermission(eventGroup, {});
    }
    if (ret != SUCCESS) {
        SGLOGE("check permission fail");
        return ret;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto iter = clientCallBacks_.find(clientId);
        if (iter == clientCallBacks_.end()) {
            SGLOGE("clientId not exist");
            return BAD_PARAM;
        }
    }
    ret = AcquireDataSubscribeManager::GetInstance().DestoryClient(eventGroup, clientId);
    if (ret != SUCCESS) {
        SGLOGI("AcquireDataSubscribeManager, DestoryClient ret=%{public}d", ret);
        return ret;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (deathRecipient_ != nullptr) {
            clientCallBacks_.at(clientId)->RemoveDeathRecipient(deathRecipient_);
        }
        clientCallBacks_.erase(clientId);
    }
    return SUCCESS;
}

ErrCode DataCollectManagerService::CreatClient(const std::string &eventGroup, const std::string &clientId,
    const sptr<IRemoteObject> &cb)
{
    SGLOGI("DataCollectManagerService, CreatClient");
    if (eventGroup == "") {
        SGLOGE("event group empty");
        return BAD_PARAM;
    }
    int32_t ret = 0;
    if (eventGroup == "securityGroup") {
        ret = IsEventGroupHasPermission(eventGroup, {});
    } else {
        ret = IsEventGroupHasPublicPermission(eventGroup, {});
    }
    if (ret != SUCCESS) {
        SGLOGE("check permission fail");
        return ret;
    }
    if (cb == nullptr) {
        SGLOGE("cb is null");
        return NULL_OBJECT;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (clientCallBacks_.find(clientId) != clientCallBacks_.end()) {
            SGLOGE("clientId exist");
            return BAD_PARAM;
        }
    }
    SgSubscribeEvent event {};
    ret = AcquireDataSubscribeManager::GetInstance().CreatClient(eventGroup, clientId, cb);
    if (ret != SUCCESS) {
        SGLOGI("AcquireDataSubscribeManager, CreatClient ret=%{public}d", ret);
        return ret;
    }
    ret = SetDeathCallBack(event, cb);
    if (ret != SUCCESS) {
        return ret;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        clientCallBacks_[clientId] = cb;
    }
    return SUCCESS;
}

ErrCode DataCollectManagerService::QueryCodeSignInfoByPath(const int fd, const int pid, std::string &resStr)
{
    SGLOGI("enter DataCollectManagerService QuerySecurityEventById");
    int32_t code = IsApiHasPermission("QueryCodeSignInfoByPath");
    if (code != SUCCESS) {
        return code;
    }
    std::string param = "fd=" + std::to_string(fd) + ",pid=" + std::to_string(pid);
    SecurityCollector::SecurityEventRuler ruler(0xffffffff06, "", "", param);
    std::vector<SecurityCollector::SecurityEvent> replyEvents {};
    int ret = SecurityCollector::DataCollection::GetInstance().QuerySecurityEvent({ruler}, replyEvents);
    if (ret != SUCCESS) {
        SGLOGE("CodeSign QuerySecurityEvent fail ret=%{public}d", ret);
        return ret;
    }
    if (replyEvents.empty()) {
        SGLOGE("CodeSign QuerySecurityEvent replyEvents empty");
        return FAILED;
    }
    resStr = replyEvents[0].GetContent();
    return SUCCESS;
}
}