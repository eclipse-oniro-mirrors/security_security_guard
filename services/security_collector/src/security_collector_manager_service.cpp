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

#include "security_collector_manager_service.h"
#include <thread>
#include <atomic>
#include <cinttypes>
#include "hisysevent.h"
#include "iservice_registry.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "system_ability_definition.h"
#include "security_collector_define.h"
#include "security_collector_log.h"
#include "data_collection.h"
#include "sg_collect_client.h"
#include "security_collector_subscriber_manager.h"
#include "security_collector_run_manager.h"
#include "security_collector_manager_callback_proxy.h"
#include "ffrt.h"
#include "ffrt_inner.h"
#include "event_define.h"
#include "tokenid_kit.h"

namespace OHOS::Security::SecurityCollector {
namespace {
    constexpr char COLLECT_EVENT_PERMISSION[] = "ohos.permission.COLLECT_SECURITY_EVENT";
    constexpr char QUERY_EVENT_PERMISSION[] = "ohos.permission.QUERY_SECURITY_EVENT";
    constexpr const char* CALLER_PID = "CALLER_PID";
    constexpr const char* EVENT_VERSION = "EVENT_VERSION";
    constexpr const char* SC_EVENT_ID = "EVENT_ID";
    constexpr const char* SUB_RET = "SUB_RET";
    constexpr const char* UNSUB_RET = "UNSUB_RET";
    constexpr const int SLEEP_INTERVAL = 5000;
    std::atomic<uint32_t> g_refCount = 0;
    ffrt::thread g_mainThread {};
    std::atomic<bool> g_flag = true;
}

REGISTER_SYSTEM_ABILITY_BY_ID(SecurityCollectorManagerService, SECURITY_COLLECTOR_MANAGER_SA_ID, true);

SecurityCollectorManagerService::SecurityCollectorManagerService(int32_t saId, bool runOnCreate)
    : SystemAbility(saId, runOnCreate)
{
    LOGW("%{public}s", __func__);
}

void SecurityCollectorManagerService::OnStart()
{
    LOGI("%{public}s", __func__);
    auto handler = [this] (const sptr<IRemoteObject> &remote) { CleanSubscriber(remote); };
    SecurityCollectorSubscriberManager::GetInstance().SetUnsubscribeHandler(handler);
    auto task = []() {
        while (g_flag) {
            ffrt::this_task::sleep_for(std::chrono::milliseconds(SLEEP_INTERVAL));
            if (g_refCount.load() != 0) {
                continue;
            }
            LOGD("Unload security collector manager SA begin.");
            auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
            if (registry == nullptr) {
                LOGE("GetSystemAbilityManager error.");
                break;
            }
            registry->UnloadSystemAbility(SECURITY_COLLECTOR_MANAGER_SA_ID);
            LOGI("Unload security collector manager SA end.");
            break;
        }
    };
    g_mainThread = ffrt::thread(task);
    if (!Publish(this)) {
        LOGE("Publish error");
    }
}

void SecurityCollectorManagerService::OnStop()
{
    g_flag = false;
    g_mainThread.join();
}

int SecurityCollectorManagerService::Dump(int fd, const std::vector<std::u16string>& args)
{
    return 0;
}

void SecurityCollectorManagerService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
}

void SecurityCollectorManagerService::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    LOGW("OnRemoveSystemAbility, systemAbilityId=%{public}d", systemAbilityId);
}

int32_t SecurityCollectorManagerService::Subscribe(const SecurityCollectorSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &callback)
{
    g_refCount.fetch_add(1);
    int32_t ret = HasPermission(QUERY_EVENT_PERMISSION);
    if (ret != SUCCESS) {
        LOGE("caller no permission");
        g_refCount.fetch_sub(1);
        return ret;
    }
    Event event = subscribeInfo.GetEvent();
    LOGI("in subscribe, subscribinfo: duration:%{public}" PRId64 ", isNotify:%{public}d, eventid:%{public}" PRId64 ","
        "version:%{public}s, extra:%{public}s", subscribeInfo.GetDuration(), (int)subscribeInfo.IsNotify(),
        event.eventId, event.version.c_str(), event.extra.c_str());
    if (!SetDeathRecipient(callback)) {
        g_refCount.fetch_sub(1);
        return NULL_OBJECT;
    }
    auto eventHandler = [this] (const std::string &appName, const sptr<IRemoteObject> &remote, const Event &event) {
        ExecuteOnNotifyByTask(remote, event);
    };
    auto subscriber = std::make_shared<SecurityCollectorSubscriber>(NOTIFY_APP_NAME,
        subscribeInfo, callback, eventHandler);
    ScSubscribeEvent subEvent;
    subEvent.pid = IPCSkeleton::GetCallingPid();
    subEvent.version = event.version;
    subEvent.eventId = event.eventId;

    if (!SecurityCollectorSubscriberManager::GetInstance().SubscribeCollector(subscriber)) {
        UnsetDeathRecipient(callback);
        subEvent.ret = BAD_PARAM;
        ReportScSubscribeEvent(subEvent);
        g_refCount.fetch_sub(1);
        return BAD_PARAM;
    }
    subEvent.ret = SUCCESS;
    ReportScSubscribeEvent(subEvent);
    LOGI("Out subscribe");
    return SUCCESS;
}

int32_t SecurityCollectorManagerService::Unsubscribe(const sptr<IRemoteObject> &callback)
{
    LOGI("In unsubscribe");
    int32_t ret = HasPermission(QUERY_EVENT_PERMISSION);
    if (ret != SUCCESS) {
        LOGE("caller no permission");
        return ret;
    }
    if (g_refCount.load() == 0) {
        LOGE("Unsubscriber event failed, subscriber count is 0");
        return FAILED;
    }
    CleanSubscriber(callback);

    ScUnsubscribeEvent subEvent;
    subEvent.pid = IPCSkeleton::GetCallingPid();
    subEvent.ret = SUCCESS;
    LOGI("SecurityCollectorManagerService, CleanSubscriber");
    ReportScUnsubscribeEvent(subEvent);

    LOGI("Out unsubscribe");
    g_refCount.fetch_sub(1);
    return SUCCESS;
}

int32_t SecurityCollectorManagerService::CollectorStart(const SecurityCollectorSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &callback)
{
    g_refCount.fetch_add(1);
    int32_t ret = HasPermission(COLLECT_EVENT_PERMISSION);
    if (ret != SUCCESS) {
        LOGE("caller no permission");
        g_refCount.fetch_sub(1);
        return ret;
    }
    Event event = subscribeInfo.GetEvent();
    int32_t collectorType = COLLECTOR_NOT_CAN_START;
    if (DataCollection::GetInstance().GetCollectorType(event.eventId, collectorType) != SUCCESS) {
        LOGE("get collector type error event id: %{public}" PRId64, event.eventId);
        g_refCount.fetch_sub(1);
        return BAD_PARAM;
    }

    if (collectorType != COLLECTOR_CAN_START) {
        LOGE("collector type not support be start, event id: %{public}" PRId64, event.eventId);
        g_refCount.fetch_sub(1);
        return BAD_PARAM;
    }
    std::string appName = GetAppName();
    LOGI("in subscribe, appname:%{public}s", appName.c_str());
    if (appName.empty()) {
        g_refCount.fetch_sub(1);
        return BAD_PARAM;
    }
    ret = CollectorStartInner(appName, subscribeInfo, event);
    if (ret != SUCCESS) {
        g_refCount.fetch_sub(1);
    }
    return ret;
}

int32_t SecurityCollectorManagerService::CollectorStartInner(const std::string &appName,
    const SecurityCollectorSubscribeInfo &subscribeInfo, const Event &event)
{
    auto eventHandler = [this] (const std::string &appName, const sptr<IRemoteObject> &remote, const Event &event) {
        LOGD("eventid:%{public}" PRId64 " callback default", event.eventId);
        auto reportEvent = [event] () {
            auto info = std::make_shared<SecurityGuard::EventInfo>(event.eventId, event.version, event.content);
            SecurityGuard::NativeDataCollectKit::ReportSecurityInfo(info);
        };
        reportEvent();
        return;
    };
    auto subscriber = std::make_shared<SecurityCollectorSubscriber>(appName, subscribeInfo, nullptr, eventHandler);
    ScSubscribeEvent subEvent;
    subEvent.pid = IPCSkeleton::GetCallingPid();
    subEvent.version = event.version;
    subEvent.eventId = event.eventId;

    if (!SecurityCollectorRunManager::GetInstance().StartCollector(subscriber)) {
        subEvent.ret = BAD_PARAM;
        ReportScSubscribeEvent(subEvent);
        return BAD_PARAM;
    }
    subEvent.ret = SUCCESS;
    ReportScSubscribeEvent(subEvent);
    LOGI("Out CollectorStart");
    return SUCCESS;
}

int32_t SecurityCollectorManagerService::CollectorStop(const SecurityCollectorSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &callback)
{
    Event event = subscribeInfo.GetEvent();
    int32_t ret = HasPermission(COLLECT_EVENT_PERMISSION);
    if (g_refCount.load() == 0) {
        LOGE("Collector stop failed, subscriber count is 0");
        return FAILED;
    }
    if (ret != SUCCESS) {
        LOGE("caller no permission");
        return ret;
    }
    std::string appName = GetAppName();
    LOGI("in CollectorStop, appname:%{public}s", appName.c_str());
    if (appName.empty()) {
        return BAD_PARAM;
    }
    auto eventHandler = [this] (const std::string &appName, const sptr<IRemoteObject> &remote, const Event &event) {
        return;
    };
    auto subscriber = std::make_shared<SecurityCollectorSubscriber>(appName, subscribeInfo, nullptr, eventHandler);
    ScSubscribeEvent subEvent;
    subEvent.pid = IPCSkeleton::GetCallingPid();
    subEvent.version = event.version;
    subEvent.eventId = event.eventId;

    if (!SecurityCollectorRunManager::GetInstance().StopCollector(subscriber)) {
        subEvent.ret = BAD_PARAM;
        ReportScSubscribeEvent(subEvent);
        return BAD_PARAM;
    }
    subEvent.ret = SUCCESS;
    ReportScSubscribeEvent(subEvent);
    LOGI("Out CollectorStop");
    g_refCount.fetch_sub(1);
    return SUCCESS;
}

void SecurityCollectorManagerService::CleanSubscriber(const sptr<IRemoteObject> &remote)
{
    LOGI("Clean Subscribe ");
    UnsetDeathRecipient(remote);
    SecurityCollectorSubscriberManager::GetInstance().UnsubscribeCollector(remote);
    SecurityCollectorSubscriberManager::GetInstance().RemoveAllFilter();
}

bool SecurityCollectorManagerService::SetDeathRecipient(const sptr<IRemoteObject> &remote)
{
    std::lock_guard<std::mutex> lock(deathRecipientMutex_);
    if (deathRecipient_ == nullptr) {
        deathRecipient_ = new (std::nothrow) SubscriberDeathRecipient(this);
        if (deathRecipient_ == nullptr) {
            LOGE("no memory");
            return false;
        }
    }
    remote->AddDeathRecipient(deathRecipient_);
    return true;
}

void SecurityCollectorManagerService::UnsetDeathRecipient(const sptr<IRemoteObject> &remote)
{
    std::lock_guard<std::mutex> lock(deathRecipientMutex_);
    if (deathRecipient_ != nullptr) {
        remote->RemoveDeathRecipient(deathRecipient_);
    }
}

void SecurityCollectorManagerService::SubscriberDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    g_refCount.fetch_sub(1);
    LOGD("SecurityCollectorManagerService In");
    if (remote == nullptr) {
        LOGE("remote object is nullptr");
        return;
    }
    sptr<IRemoteObject> object = remote.promote();
    if (object == nullptr) {
        LOGE("object is nullptr");
        return;
    }
    sptr<SecurityCollectorManagerService> service = service_.promote();
    if (service == nullptr) {
        LOGE("service is nullptr");
        return;
    }
    service->CleanSubscriber(object);
    LOGD("SecurityCollectorManagerService out");
}

void SecurityCollectorManagerService::ReportScSubscribeEvent(const ScSubscribeEvent &event)
{
    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::SECURITY_GUARD, "SC_EVENT_SUBSCRIBE",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC, CALLER_PID, event.pid,
        EVENT_VERSION, event.version, SC_EVENT_ID, event.eventId, SUB_RET, event.ret);
}

void SecurityCollectorManagerService::ReportScUnsubscribeEvent(const ScUnsubscribeEvent &event)
{
    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::SECURITY_GUARD, "SC_EVENT_UNSUBSCRIBE",
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC, CALLER_PID, event.pid, UNSUB_RET, event.ret);
}

void SecurityCollectorManagerService::ExecuteOnNotifyByTask(const sptr<IRemoteObject> &remote, const Event &event)
{
    auto proxy = iface_cast<ISecurityCollectorManagerCallback>(remote);
    if (proxy != nullptr) {
        LOGD("report to proxy");
        auto task = [proxy, event] () {
            proxy->OnNotify(event);
        };
        if (event.eventId == SecurityCollector::FILE_EVENTID ||
            event.eventId == SecurityCollector::PROCESS_EVENTID ||
            event.eventId == SecurityCollector::NETWORK_EVENTID) {
            ffrt::submit(task, {}, {}, ffrt::task_attr().qos(ffrt::qos_background));
        } else {
            ffrt::submit(task);
        }
    } else {
        LOGE("report proxy is null");
    }
}

int32_t SecurityCollectorManagerService::QuerySecurityEvent(const std::vector<SecurityEventRuler> rulers,
    std::vector<SecurityEvent> &events)
{
    g_refCount.fetch_add(1);
    LOGD("begin QuerySecurityEvent");
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int code = AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, QUERY_EVENT_PERMISSION);
    if (code != AccessToken::PermissionState::PERMISSION_GRANTED) {
        LOGE("caller no permission");
        g_refCount.fetch_sub(1);
        return NO_PERMISSION;
    }

    if (DataCollection::GetInstance().QuerySecurityEvent(rulers, events) != SUCCESS) {
        LOGI("QuerySecurityEvent error");
        g_refCount.fetch_sub(1);
        return READ_ERR;
    }
    g_refCount.fetch_sub(1);
    return SUCCESS;
}

std::string SecurityCollectorManagerService::GetAppName()
{
    AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenType(tokenId);
    if (tokenType == AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        AccessToken::HapTokenInfo hapTokenInfo;
        int ret = AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, hapTokenInfo);
        if (ret != 0) {
            LOGE("failed to get hap token info, result = %{public}d", ret);
            return "";
        }
        return hapTokenInfo.bundleName;
    } else if (tokenType == AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        AccessToken::NativeTokenInfo nativeTokenInfo;
        int ret = AccessToken::AccessTokenKit::GetNativeTokenInfo(tokenId, nativeTokenInfo);
        if (ret != 0) {
            LOGE("failed to get native token info, result = %{public}d", ret);
            return "";
        }
        return nativeTokenInfo.processName;
    }
    LOGE("failed to get app name");
    return "";
}

int32_t SecurityCollectorManagerService::HasPermission(const std::string &permission)
{
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int code = AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permission);
    if (code != AccessToken::PermissionState::PERMISSION_GRANTED) {
        return NO_PERMISSION;
    }

    return SUCCESS;
}
}