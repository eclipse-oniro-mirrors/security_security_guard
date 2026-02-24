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
#include "iservice_registry.h"
#include "data_collect_manager.h"
#include <chrono>
#include "fdsan_fd.h"
#include "directory_ex.h"
#include "data_collect_manager_idl_proxy.h"
#include "data_collect_manager_idl.h"
#include "security_event_ruler.h"
#include "security_event_query_callback_service.h"
#include "security_guard_define.h"
#include "acquire_data_manager_callback_service.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "data_collect_manager_callback_service.h"
#include "security_collector_manager_callback_service.h"
#include "security_collector_subscribe_info.h"

namespace {
    constexpr uint32_t MAX_RESUB_COUNTS = 3;
    const std::string SECURITY_GROUP = "securityGroup";
}

namespace OHOS::Security::SecurityGuard {
DataCollectManager& DataCollectManager::GetInstance()
{
    static DataCollectManager instance;
    return instance;
};

DataCollectManager::DataCollectManager() : callback_(new (std::nothrow) AcquireDataManagerCallbackService())
{
    auto func = [this](const SecurityCollector::Event &event) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto &iter : subscribers_) {
            if (iter->GetSubscribeInfo().GetEvent().eventId == event.eventId) {
                iter->OnNotify(event);
            }
        }
    };
    if (callback_ != nullptr) {
        callback_->RegistCallBack(func);
        std::string timeStr = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        std::string ptrStr = std::to_string(reinterpret_cast<int64_t>(callback_.GetRefPtr()));
        std::size_t hash = std::hash<std::string>{}(timeStr + ptrStr);
        sdkFlag_ = "sdk" + std::to_string(hash);
    }
}

int32_t DataCollectManager::QuerySecurityEvent(std::vector<SecurityCollector::SecurityEventRuler> rulers,
    std::shared_ptr<SecurityEventQueryCallback> callback)
{
    return QuerySecurityEvent(rulers, callback, SECURITY_GROUP);
}

int32_t DataCollectManager::QuerySecurityEvent(std::vector<SecurityCollector::SecurityEventRuler> rulers,
    std::shared_ptr<SecurityEventQueryCallback> callback, const std::string &eventGroup)
{
    if (callback == nullptr) {
        SGLOGE("callback is null");
        return NULL_OBJECT;
    }
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return FAILED;
    }

    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<DataCollectManagerIdl>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }

    auto obj = new (std::nothrow) SecurityEventQueryCallbackService(callback);
    if (obj == nullptr) {
        SGLOGE("obj is null");
        return NULL_OBJECT;
    }

    int32_t ret = proxy->QuerySecurityEvent(rulers, obj, eventGroup);
    if (ret != 0) {
        SGLOGE("QuerySecurityEvent error, ret=%{public}d", ret);
        return ret;
    }
    return 0;
}

int32_t DataCollectManager::QuerySecurityEventById(std::vector<SecurityCollector::SecurityEventRuler> rulers,
    std::shared_ptr<SecurityEventQueryCallback> callback, const std::string &eventGroup)
{
    if (callback == nullptr) {
        SGLOGE("callback is null");
        return NULL_OBJECT;
    }
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return FAILED;
    }

    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<DataCollectManagerIdl>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }

    auto obj = new (std::nothrow) SecurityEventQueryCallbackService(callback);
    if (obj == nullptr) {
        SGLOGE("obj is null");
        return NULL_OBJECT;
    }

    int32_t ret = proxy->QuerySecurityEventById(rulers, obj, eventGroup);
    if (ret != 0) {
        SGLOGE("QuerySecurityEventById error, ret=%{public}d", ret);
        return ret;
    }
    return 0;
}

int32_t DataCollectManager::QuerySecurityEventConfig(std::string &result)
{
    SGLOGI("Start DataCollectManager QuerySecurityEventConfig");
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return FAILED;
    }
    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    if (object == nullptr) {
        SGLOGE("object is nullptr");
        return FAILED;
    }
    auto proxy = iface_cast<DataCollectManagerIdl>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return FAILED;
    }
    return proxy->QuerySecurityEventConfig(result);
}

void DataCollectManager::DeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    if (remote == nullptr) {
        SGLOGE("remote object is nullptr");
        return;
    }
    sptr<IRemoteObject> object = remote.promote();
    if (object == nullptr) {
        SGLOGE("object is nullptr");
        return;
    }
    object->RemoveDeathRecipient(this);
    DataCollectManager::GetInstance().HandleDecipient();
}

void DataCollectManager::HandleDecipient()
{
    std::set<std::shared_ptr<SecurityCollector::ICollectorSubscriber>> tmp {};
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (count_ >= MAX_RESUB_COUNTS) {
            SGLOGE("reSubscriber too many times");
            return;
        }
        if (callback_ == nullptr) {
            SGLOGE("callback is nullptr");
            return;
        }
        subscribers_.swap(tmp);
    }
    // wait sg start up
    sleep(1);
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return;
    }
    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<DataCollectManagerIdl>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return;
    }
    if (deathRecipient_ == nullptr || !object->AddDeathRecipient(deathRecipient_)) {
        SGLOGE("Failed to add death recipient");
        return;
    }
    for (const auto &iter : tmp) {
        int32_t ret = Subscribe(iter);
        if (ret != SUCCESS) {
            SGLOGE("ReSubscribe fail, ret=%{public}d", ret);
        }
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        count_++;
    }
}

int32_t DataCollectManager::SetDeathRecipient(const sptr<IRemoteObject> &remote)
{
    if (deathRecipient_ == nullptr) {
        deathRecipient_ = new (std::nothrow) DeathRecipient();
        if (deathRecipient_ == nullptr) {
            SGLOGE("deathRecipient_ is nullptr.");
            return NULL_OBJECT;
        }
        if (!remote->AddDeathRecipient(deathRecipient_)) {
            SGLOGE("Failed to add death recipient");
        }
    }
    return SUCCESS;
}

int32_t DataCollectManager::Subscribe(const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &subscriber)
{
    SGLOGI("enter DataCollectManager Subscribe");
    if (subscriber == nullptr) {
        SGLOGE("subscriber is nullptr");
        return NULL_OBJECT;
    }
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return NULL_OBJECT;
    }
    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<DataCollectManagerIdl>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (callback_ == nullptr) {
            SGLOGE("callback_ is nullptr");
            return NULL_OBJECT;
        }
        if (subscribers_.count(subscriber) != 0) {
            SGLOGE("Already subscribed");
            return BAD_PARAM;
        }
        int32_t ret = SetDeathRecipient(object);
        if (ret != SUCCESS) {
            SGLOGI("SetDeathRecipient fail, ret=%{public}d", ret);
            return ret;
        }
    }
    if (!IsCurrentSubscriberEventIdExist(subscriber)) {
        int32_t ret = proxy->Subscribe(subscriber->GetSubscribeInfo(), callback_, sdkFlag_);
        if (ret != SUCCESS) {
            SGLOGI("Subscribe result, ret=%{public}d", ret);
            return ret;
        }
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        subscribers_.insert(subscriber);
        SGLOGI("current subscrbe size %{public}zu", subscribers_.size());
    }
    return SUCCESS;
}

int32_t DataCollectManager::Unsubscribe(const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &subscriber)
{
    SGLOGI("enter DataCollectManager UnSubscribe");
    if (subscriber == nullptr) {
        SGLOGE("subscriber is nullptr");
        return NULL_OBJECT;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (callback_ == nullptr) {
            SGLOGE("callback is null");
            return NULL_OBJECT;
        }
        if (subscribers_.count(subscriber) == 0) {
            SGLOGE("Not subscribed");
            return BAD_PARAM;
        }
    }
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return NULL_OBJECT;
    }
    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<DataCollectManagerIdl>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        subscribers_.erase(subscriber);
    }
    if (!IsCurrentSubscriberEventIdExist(subscriber)) {
        int32_t ret = proxy->Unsubscribe(subscriber->GetSubscribeInfo(), callback_, sdkFlag_);
        if (ret != SUCCESS) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                subscribers_.insert(subscriber);
            }
            return ret;
        }
        SGLOGI("Unsubscribe result, ret=%{public}d", ret);
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        SGLOGI("current subscrbe size %{public}zu", subscribers_.size());
    }
    return SUCCESS;
}

bool DataCollectManager::IsCurrentSubscriberEventIdExist(
    const std::shared_ptr<SecurityCollector::ICollectorSubscriber> &sub)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &i : subscribers_) {
        if (i->GetSubscribeInfo().GetEvent().eventId == sub->GetSubscribeInfo().GetEvent().eventId) {
            return true;
        }
    }
    return false;
}

int32_t DataCollectManager::ReportSecurityEvent(const std::shared_ptr<EventInfo> &info, bool isSync)
{
    SGLOGD("enter DataCollectManager ReportSecurityEvent");
    if (info == nullptr) {
        return BAD_PARAM;
    }
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return NULL_OBJECT;
    }
    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<DataCollectManagerIdl>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }

    int64_t eventId = info->GetEventId();
    std::string version = info->GetVersion();
    std::string content = info->GetContent();
    std::string date = SecurityGuardUtils::GetDate();
    int32_t ret = SUCCESS;
    if (isSync) {
        ret = proxy->RequestDataSubmit(eventId, version, date, content);
    } else {
        ret = proxy->RequestDataSubmitAsync(eventId, version, date, content);
    }
    if (ret != SUCCESS) {
        SGLOGE("RequestSecurityInfo error, ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

int32_t DataCollectManager::SecurityGuardConfigUpdate(int32_t fd, const std::string &name)
{
    SGLOGI("enter DataCollectManager SecurityGuardConfigUpdate");
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return NULL_OBJECT;
    }
    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<DataCollectManagerIdl>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }
    int32_t ret = proxy->ConfigUpdate(fd, name);
    if (ret != SUCCESS) {
        SGLOGE("ConfigUpdate error, ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

int32_t DataCollectManager::StartCollector(const SecurityCollector::Event &event,
    int64_t duration)
{
    SGLOGI("enter DataCollectManager StartCollector");
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return NULL_OBJECT;
    }

    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<DataCollectManagerIdl>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }

    SecurityCollector::SecurityCollectorSubscribeInfo subscriberInfo{event, duration, true};
    sptr<SecurityCollector::SecurityCollectorManagerCallbackService> callback =
        new (std::nothrow) SecurityCollector::SecurityCollectorManagerCallbackService(nullptr);
    if (callback == nullptr) {
        SGLOGE("callback is null");
        return NULL_OBJECT;
    }

    int32_t ret = proxy->CollectorStart(subscriberInfo, callback);
    SGLOGI("StartCollector result, ret=%{public}d", ret);
    return ret;
}

int32_t DataCollectManager::StopCollector(const SecurityCollector::Event &event)
{
    SGLOGI("in DataCollectManager StopCollector");
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return NULL_OBJECT;
    }

    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<DataCollectManagerIdl>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }

    SecurityCollector::SecurityCollectorSubscribeInfo subscriberInfo{event, -1, true};
    sptr<SecurityCollector::SecurityCollectorManagerCallbackService> callback =
        new (std::nothrow) SecurityCollector::SecurityCollectorManagerCallbackService(nullptr);
    if (callback == nullptr) {
        SGLOGE("callback is null");
        return NULL_OBJECT;
    }

    int32_t ret = proxy->CollectorStop(subscriberInfo, callback);
    SGLOGI("StopCollector result, ret=%{public}d", ret);
    return ret;
}

int32_t DataCollectManager::RequestSecurityEventInfo(std::string &devId, std::string &eventList,
    RequestRiskDataCallback callback)
{
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return NULL_OBJECT;
    }

    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<DataCollectManagerIdl>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return NULL_OBJECT;
    }

    auto obj = new (std::nothrow) DataCollectManagerCallbackService(callback);
    if (obj == nullptr) {
        SGLOGE("stub is null");
        return NULL_OBJECT;
    }
    int32_t ret = proxy->RequestRiskData(devId, eventList, obj);
    if (ret != 0) {
        SGLOGE("RequestSecurityEventInfo error, ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

int32_t DataCollectManager::QueryCodeSignInfoByPath(const std::string &filePath, std::string &result)
{
    SGLOGI("Start DataCollectManager QueryCodeSignInfoByPath");
    std::string realPath {};
    if (!PathToRealPath(filePath, realPath)) {
        SGLOGE("PathToRealPath fail");
        return FILE_NOT_FOUND;
    }
    auto fdsan = std::make_shared<FdsanFd>(open(realPath.c_str(), O_RDONLY));
    if (fdsan->Get() < 0) {
        SGLOGE("open file fail! reason %{publics}s", strerror(errno));
        return FILE_NOT_FOUND;
    }
    auto pid = getpid();
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return FAILED;
    }
    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    if (object == nullptr) {
        SGLOGE("object is nullptr");
        return FAILED;
    }
    auto proxy = iface_cast<DataCollectManagerIdl>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return FAILED;
    }
    return proxy->QueryCodeSignInfoByPath(fdsan->Get(), pid, result);
}
}