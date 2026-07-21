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
#include "iservice_registry.h"
#include "security_guard_log.h"
#include "data_collect_manager_idl_proxy.h"
#include "data_collect_manager_idl.h"
#include "security_event_filter.h"
#include "security_guard_define.h"
#include "acquire_data_manager_callback_service.h"
namespace OHOS::Security::SecurityGuard {
namespace {
    std::set<std::shared_ptr<EventSubscribeClient>> g_clients{};
    std::mutex g_clientMutex{};

}

void EventSubscribeClient::Deleter(EventSubscribeClient *client)
{
    SGLOGI("enter EventSubscribeClient Deleter");
    if (client == nullptr) {
        return;
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
    std::lock_guard<std::mutex> lock(g_clientMutex);
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
        client->deathRecipient_ = new (std::nothrow) DeathRecipient();
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
    return SUCCESS;
}
}