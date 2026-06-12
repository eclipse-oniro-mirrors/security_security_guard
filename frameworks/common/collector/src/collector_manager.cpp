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
#include "collector_manager.h"

#include "iservice_registry.h"
#include "security_collector_manager_proxy.h"
#include "security_collector_manager_callback_service.h"
#include "security_collector_define.h"
#include "security_collector_log.h"
#include "collector_service_loader.h"
#include "sys_binder.h"

namespace OHOS::Security::SecurityCollector {
int32_t CollectorManager::SubscribeImpl(const std::shared_ptr<ICollectorSubscriber> &subscriber)
{
    if (subscriber == nullptr) {
        LOGE("subscriber is null");
        return BAD_PARAM;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (eventListeners_.find(subscriber) != eventListeners_.end()) {
        LOGE("Already subscribed");
        return BAD_PARAM;
    }

    auto object = CollectorServiceLoader::GetInstance().LoadCollectorService();
    if (object == nullptr) {
        LOGE("object is null");
        return NULL_OBJECT;
    }
    auto proxy = iface_cast<ISecurityCollectorManager>(object);
    if (proxy == nullptr) {
        LOGE("proxy is null");
        return NULL_OBJECT;
    }
    if (deathRecipient_ == nullptr) {
        deathRecipient_ = new (std::nothrow) DeathRecipient();
        if (deathRecipient_ == nullptr) {
            LOGE("deathRecipient_ is null");
            return NULL_OBJECT;
        }
    }
    if (!object->AddDeathRecipient(deathRecipient_)) {
        LOGE("Failed to add death recipient");
        return NULL_OBJECT;
    }

    sptr<SecurityCollectorManagerCallbackService> callback =
        new (std::nothrow) SecurityCollectorManagerCallbackService(subscriber);
    if (callback == nullptr) {
        LOGE("callback is null");
        return NULL_OBJECT;
    }
    int32_t ret = proxy->Subscribe(subscriber->GetSubscribeInfo(), callback);
    if (ret == SUCCESS) {
        eventListeners_[subscriber] = callback;
    }
    LOGI("Subscribe result, ret=%{public}d", ret);
    return ret;
}

int32_t CollectorManager::Subscribe(const std::shared_ptr<ICollectorSubscriber> &subscriber)
{
    LOGI("enter CollectorManager Subscribe");
    int32_t ret = SubscribeImpl(subscriber);
    if (ret == BR_DEAD_REPLY) {
        LOGE("retry CollectorManager Subscribe");
        return SubscribeImpl(subscriber);
    }
    return ret;
}

int32_t CollectorManager::UnsubscribeImpl(const std::shared_ptr<ICollectorSubscriber> &subscriber)
{
    if (subscriber == nullptr) {
        LOGE("subscriber is null");
        return BAD_PARAM;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (eventListeners_.find(subscriber) == eventListeners_.end()) {
        LOGE("Not subscribed");
        return BAD_PARAM;
    }
    auto object = CollectorServiceLoader::GetInstance().LoadCollectorService();
    if (object == nullptr) {
        LOGE("object is null");
        return NULL_OBJECT;
    }
    auto proxy = iface_cast<ISecurityCollectorManager>(object);
    if (proxy == nullptr) {
        LOGE("Proxy is null");
        return NULL_OBJECT;
    }

    int32_t ret = proxy->Unsubscribe(eventListeners_[subscriber]);
    LOGI("Unsubscribe result, ret=%{public}d", ret);
    eventListeners_.erase(subscriber);
    return ret;
}

int32_t CollectorManager::Unsubscribe(const std::shared_ptr<ICollectorSubscriber> &subscriber)
{
    LOGI("enter CollectorManager Unsubscribe");
    int32_t ret = UnsubscribeImpl(subscriber);
    if (ret == BR_DEAD_REPLY) {
        LOGE("retry CollectorManager Unsubscribe");
        return UnsubscribeImpl(subscriber);
    }
    return ret;
}

void CollectorManager::DeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    if (remote == nullptr) {
        LOGE("remote object is nullptr");
        return;
    }
    sptr<IRemoteObject> object = remote.promote();
    if (object == nullptr) {
        LOGE("object is nullptr");
        return;
    }
    object->RemoveDeathRecipient(this);
    CollectorManager::GetInstance().HandleDecipient();
}

void CollectorManager::HandleDecipient()
{
    std::lock_guard<std::mutex> lock(mutex_);
    eventListeners_.clear();
}

int32_t CollectorManager::QuerySecurityEventImpl(const std::vector<SecurityEventRuler> rulers,
    std::vector<SecurityEvent> &events)
{
    auto object = CollectorServiceLoader::GetInstance().LoadCollectorService();
    if (object == nullptr) {
        LOGE("object is null");
        return NULL_OBJECT;
    }
    auto proxy = iface_cast<ISecurityCollectorManager>(object);
    if (proxy == nullptr) {
        LOGE("proxy is null");
        return NULL_OBJECT;
    }

    int32_t ret = proxy->QuerySecurityEvent(rulers, events);
    if (ret != SUCCESS) {
        LOGI("QuerySecurityEvent failed, ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

int32_t CollectorManager::QuerySecurityEvent(const std::vector<SecurityEventRuler> rulers,
    std::vector<SecurityEvent> &events)
{
    LOGI("begin collector QuerySecurityEvent");
    int32_t ret = QuerySecurityEventImpl(rulers, events);
    if (ret == BR_DEAD_REPLY) {
        LOGE("retry collector QuerySecurityEvent");
        return QuerySecurityEventImpl(rulers, events);
    }
    return ret;
}

int32_t CollectorManager::CollectorStartImpl(const SecurityCollector::SecurityCollectorSubscribeInfo &subscriber)
{
    auto object = CollectorServiceLoader::GetInstance().LoadCollectorService();
    if (object == nullptr) {
        LOGE("object is null");
        return NULL_OBJECT;
    }
    auto proxy = iface_cast<ISecurityCollectorManager>(object);
    if (proxy == nullptr) {
        LOGE("proxy is null");
        return NULL_OBJECT;
    }
    sptr<SecurityCollector::SecurityCollectorManagerCallbackService> callback =
        new (std::nothrow) SecurityCollector::SecurityCollectorManagerCallbackService(nullptr);
    if (callback == nullptr) {
        LOGE("callback is null");
        return NULL_OBJECT;
    }
    int32_t ret = proxy->CollectorStart(subscriber, callback);
    if (ret != SUCCESS) {
        LOGI("CollectorStart failed, ret=%{public}d", ret);
        return ret;
    }
    LOGI("CollectorStart result, ret=%{public}d", ret);
    return SUCCESS;
}

int32_t CollectorManager::CollectorStart(const SecurityCollector::SecurityCollectorSubscribeInfo &subscriber)
{
    LOGI("enter CollectorManager CollectorStart");
    int32_t ret = CollectorStartImpl(subscriber);
    if (ret == BR_DEAD_REPLY) {
        LOGE("retry CollectorManager CollectorStartImpl");
        return CollectorStartImpl(subscriber);
    }
    return ret;
}

int32_t CollectorManager::CollectorStopImpl(const SecurityCollector::SecurityCollectorSubscribeInfo &subscriber)
{
    auto object = CollectorServiceLoader::GetInstance().LoadCollectorService();
    if (object == nullptr) {
        LOGE("object is null");
        return NULL_OBJECT;
    }
    auto proxy = iface_cast<ISecurityCollectorManager>(object);
    if (proxy == nullptr) {
        LOGE("proxy is null");
        return NULL_OBJECT;
    }
    sptr<SecurityCollector::SecurityCollectorManagerCallbackService> callback =
        new (std::nothrow) SecurityCollector::SecurityCollectorManagerCallbackService(nullptr);
    if (callback == nullptr) {
        LOGE("callback is null");
        return NULL_OBJECT;
    }
    int32_t ret = proxy->CollectorStop(subscriber, callback);
    if (ret != SUCCESS) {
        LOGI("CollectorStop failed, ret=%{public}d", ret);
        return ret;
    }
    LOGI("CollectorStop result, ret=%{public}d", ret);
    return SUCCESS;
}

int32_t CollectorManager::CollectorStop(const SecurityCollector::SecurityCollectorSubscribeInfo &subscriber)
{
    LOGI("enter CollectorManager CollectorStop");
    int32_t ret = CollectorStopImpl(subscriber);
    if (ret == BR_DEAD_REPLY) {
        LOGE("retry CollectorManager CollectorStopImpl");
        return CollectorStopImpl(subscriber);
    }
    return ret;
}
}