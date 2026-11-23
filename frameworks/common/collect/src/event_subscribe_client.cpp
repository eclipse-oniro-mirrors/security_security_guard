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
#include "event_subscribe_client.h"
#include <algorithm>
#include <chrono>
#include "ffrt.h"
#include "iservice_registry.h"
#include "security_guard_log.h"
#include "data_collect_manager_idl_proxy.h"
#include "data_collect_manager_idl.h"
#include "security_event_filter.h"
#include "security_guard_define.h"
#include "acquire_data_manager_callback_service.h"
namespace OHOS::Security::SecurityGuard {
namespace {
    ffrt::mutex g_clientMutex{};
    ffrt::mutex g_mutex_{};
    constexpr int RECONNECT_RETRY_DELAY_SECONDS[] = {1, 5, 15, 30, 60, 60, 60, 60, 60};
}

void EventSubscribeClient::Deleter(EventSubscribeClient *client)
{
    SGLOGI("enter EventSubscribeClient Deleter");
    if (client == nullptr) {
        return;
    }
    // 在销毁服务端 client 之前，先排空在途 OnNotify 并清空回调。
    // 本函数在最后一个 shared_ptr 释放时同步执行。当调用方把 client_ 作为对象成员时，
    // Deleter 在调用方析构函数内部执行，此时调用方内存仍然有效，
    // 在途回调可安全访问其状态；ClearCallBack 返回后不会再触发任何用户回调，
    // 随后销毁调用方状态即不存在 UAF。
    // 注意：若用户回调内部释放了最后一个 shared_ptr，会在此处等待自身持有的
    // notifyMutex_ 而死锁，调用方必须避免在回调内销毁 client。
    if (client->callback_ != nullptr) {
        client->callback_->ClearCallBack();
    }
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry != nullptr) {
        auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
        auto proxy = iface_cast<DataCollectManagerIdl>(object);
        if (proxy != nullptr) {
            proxy->DestoryClient(client->eventGroup_, client->clientId_);
            if (client->deathRecipient_ != nullptr) {
                object->RemoveDeathRecipient(client->deathRecipient_);
            }
        }
    }
    delete client;
}

int32_t EventSubscribeClient::CreatClient(const std::string &eventGroup, EventCallback callback,
    std::shared_ptr<EventSubscribeClient> &client)
{
    SGLOGI("enter EventSubscribeClient CreatClient");
    std::lock_guard<ffrt::mutex> lock(g_clientMutex);
    if (callback == nullptr) {
        SGLOGE("callback is nullptr");
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
    auto serviceCallback = new (std::nothrow) AcquireDataManagerCallbackService();
    if (serviceCallback == nullptr) {
        SGLOGE("serviceCallback is null");
        return NULL_OBJECT;
    }
    serviceCallback->RegistCallBack(callback);
    std::string clientId = ConstructClientId(serviceCallback);
    int32_t ret = proxy->CreatClient(eventGroup, clientId, serviceCallback);
    if (ret != SUCCESS) {
        SGLOGI("NewClient result, ret=%{public}d", ret);
        return ret;
    }
    client = std::shared_ptr<EventSubscribeClient>(new EventSubscribeClient(), Deleter);
    client->callback_ = serviceCallback;
    client->eventGroup_ = eventGroup;
    client->clientId_ = clientId;
    ret = SetDeathRecipient(client, object);
    if (ret != SUCCESS) {
        SGLOGE("SetDeathRecipient fail ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

std::string EventSubscribeClient::ConstructClientId(const AcquireDataManagerCallbackService *serviceCallback)
{
    std::string timeStr = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    std::string ptrStr = std::to_string(reinterpret_cast<int64_t>(serviceCallback));
    std::size_t hash = std::hash<std::string>{}(timeStr + ptrStr);
    return std::to_string(hash);
}

int32_t EventSubscribeClient::SetDeathRecipient(std::shared_ptr<EventSubscribeClient> client,
    const sptr<IRemoteObject> &remote)
{
    if (client->deathRecipient_ == nullptr) {
        client->deathRecipient_ = new (std::nothrow) DeathRecipient(client);
        if (client->deathRecipient_ == nullptr) {
            SGLOGE("deathRecipient_ is nullptr.");
            return NULL_OBJECT;
        }
        if (!remote->AddDeathRecipient(client->deathRecipient_)) {
            SGLOGE("Failed to add death recipient");
        }
    }
    return SUCCESS;
}

void EventSubscribeClient::DeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    SGLOGI("DataCollectManagerService died, try to recover EventSubscribeClient state");
    auto client = client_.lock();
    if (client == nullptr) {
        SGLOGE("client is nullptr");
        return;
    }
    sptr<IRemoteObject> object = remote.promote();
    if (object != nullptr) {
        object->RemoveDeathRecipient(this);
    }
    // avoid blocking binder thread
    ffrt::submit([client]() {client->HandleDeath();});
}

sptr<IRemoteObject> EventSubscribeClient::ReconnectService()
{
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return nullptr;
    }
    sptr<IRemoteObject> object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    if (object == nullptr || deathRecipient_ == nullptr || !object->AddDeathRecipient(deathRecipient_)) {
        SGLOGE("Failed to reconnect service");
        return nullptr;
    }
    return object;
}

void EventSubscribeClient::HandleDeath()
{
    std::set<int64_t> events;
    std::vector<std::shared_ptr<EventMuteFilter>> filters;
    {
        std::lock_guard<ffrt::mutex> lock(g_mutex_);
        events = subscribedEventIds_;
        filters = filters_;
    }
    for (int delay : RECONNECT_RETRY_DELAY_SECONDS) {
        ffrt::this_task::sleep_for(std::chrono::seconds(delay));
        sptr<IRemoteObject> object = ReconnectService();
        if (object == nullptr) {
            continue;
        }
        auto proxy = iface_cast<DataCollectManagerIdl>(object);
        if (proxy == nullptr || callback_ == nullptr) {
            SGLOGE("proxy or callback is null");
            continue;
        }
        int32_t ret = proxy->CreatClient(eventGroup_, clientId_, callback_);
        if (ret != SUCCESS) {
            SGLOGE("ReCreateClient fail, clientId=%{public}s, ret=%{public}d", clientId_.c_str(), ret);
            continue;
        }
        for (int64_t eventId : events) {
            int32_t code = proxy->Subscribe(eventId, clientId_);
            if (code != SUCCESS) {
                SGLOGE("ReSubscribe fail, eventId=%{public}lld, ret=%{public}d",
                    static_cast<long long>(eventId), code);
            }
        }
        for (const auto &filter : filters) {
            if (filter == nullptr) {
                continue;
            }
            SecurityEventFilter innerFilter(*filter);
            int32_t code = proxy->AddFilter(innerFilter, clientId_);
            if (code != SUCCESS) {
                SGLOGE("ReAddFilter fail, ret=%{public}d", code);
            }
        }
        return;
    }
    SGLOGE("recover EventSubscribeClient fail, clientId=%{public}s", clientId_.c_str());
}

int32_t EventSubscribeClient::Subscribe(int64_t eventId)
{
    SGLOGI("enter EventSubscribeClient Subscribe");
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
    int32_t ret = proxy->Subscribe(eventId, clientId_);
    if (ret != SUCCESS) {
        SGLOGI("Subscribe result, ret=%{public}d", ret);
        return ret;
    }
    {
        std::lock_guard<ffrt::mutex> lock(g_mutex_);
        subscribedEventIds_.insert(eventId);
    }
    return SUCCESS;
}

int32_t EventSubscribeClient::Unsubscribe(int64_t eventId)
{
    SGLOGI("enter EventSubscribeClient UnSubscribe");
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
    int32_t ret = proxy->Unsubscribe(eventId, clientId_);
    if (ret != SUCCESS) {
        SGLOGI("UnSubscribe result, ret=%{public}d", ret);
        return ret;
    }
    {
        std::lock_guard<ffrt::mutex> lock(g_mutex_);
        subscribedEventIds_.erase(eventId);
    }
    return SUCCESS;
}

int32_t EventSubscribeClient::AddFilter(const std::shared_ptr<EventMuteFilter> &filter)
{
    SGLOGI("enter EventSubscribeClient AddFilter");
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
    if (filter == nullptr) {
        SGLOGE("subscribeMute is null");
        return NULL_OBJECT;
    }
    SecurityEventFilter innerFilter(*filter);
    int32_t ret = proxy->AddFilter(innerFilter, clientId_);
    if (ret != SUCCESS) {
        SGLOGI("UnSubscribe result, ret=%{public}d", ret);
        return ret;
    }
    {
        std::lock_guard<ffrt::mutex> lock(g_mutex_);
        filters_.push_back(filter);
    }
    return SUCCESS;
}
int32_t EventSubscribeClient::RemoveFilter(const std::shared_ptr<EventMuteFilter> &filter)
{
    SGLOGI("enter EventSubscribeClient RemoveFilter");
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
    if (filter == nullptr) {
        SGLOGE("subscribeMute is null");
        return NULL_OBJECT;
    }
    SecurityEventFilter innerFilter(*filter);
    int32_t ret = proxy->RemoveFilter(innerFilter, clientId_);
    if (ret != SUCCESS) {
        SGLOGI("RemoveFilter result, ret=%{public}d", ret);
        return ret;
    }
    {
        std::lock_guard<ffrt::mutex> lock(g_mutex_);
        auto it = std::find_if(filters_.begin(), filters_.end(),
            [&filter](const std::shared_ptr<EventMuteFilter> &f) {
                return f != nullptr && f->eventId == filter->eventId && f->isInclude == filter->isInclude &&
                    f->type == filter->type && f->mutes == filter->mutes;
            });
        if (it != filters_.end()) {
            filters_.erase(it);
        }
    }
    return SUCCESS;
}

void EventSubscribeClient::ClearCallBack()
{
    // 注意：禁止在用户回调内部（OnNotify 触发的执行流）调用本接口，
    // 否则会因等待自身持有的 notifyMutex_ 而死锁。
    if (callback_ != nullptr) {
        callback_->ClearCallBack();
    }
}
}
