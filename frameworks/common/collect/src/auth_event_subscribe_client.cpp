/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "auth_event_subscribe_client.h"

#include <chrono>
#include <cinttypes>

#include "ffrt.h"
#include "iservice_registry.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "auth_event_session_proxy.h"
#include "data_collect_manager_idl_proxy.h"
#include "data_collect_manager_idl.h"
#include "i_data_collect_manager.h"

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
namespace OHOS::Security::SecurityGuard {
namespace {
    ffrt::mutex g_clientMutex{};
    ffrt::mutex g_mutex_{};
    constexpr int RECONNECT_RETRY_DELAY_SECONDS[] = {1, 5, 15, 30, 60, 60, 60, 60, 60};
}

AuthEventSubscribeClient::AuthEventSubscribeClient(ConstructTag) : AuthEventSubscribeClient() {}

AuthEventSubscribeClient::~AuthEventSubscribeClient()
{
    // 本函数在最后一个 shared_ptr 释放时同步执行。当调用方把 client 作为对象成员时，
    // 析构在调用方析构函数内部执行，此时调用方内存仍然有效，
    // 在途回调可安全访问其状态；Release 返回后不会再触发任何用户回调，
    // 随后销毁调用方状态即不存在 UAF。
    // 注意：若用户回调内部释放了最后一个 shared_ptr，会因等待自身持有的
    // notifyMutex_ 而死锁，调用方必须避免在回调内销毁 client。
    Release();
}

void AuthEventSubscribeClient::Release()
{
    if (callback_ != nullptr) {
        callback_->ClearCallBack();
    }
    sptr<IRemoteObject> sessionRemote;
    sptr<IRemoteObject::DeathRecipient> deathRecipient;
    {
        std::lock_guard<ffrt::mutex> lock(g_mutex_);
        deleted_ = true;
        sessionRemote = sessionRemote_;
        sessionRemote_ = nullptr;
        deathRecipient = deathRecipient_;
    }
    DestroyRemoteObjects(sessionRemote, deathRecipient);
}

void AuthEventSubscribeClient::DestroyRemoteObjects(const sptr<IRemoteObject> &sessionRemote,
    const sptr<IRemoteObject::DeathRecipient> &deathRecipient)
{
    if (sessionRemote != nullptr) {
        auto session = iface_cast<AuthEventSession>(sessionRemote);
        if (session != nullptr) {
            session->Destroy();
        }
    }
    if (deathRecipient != nullptr) {
        auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (registry != nullptr) {
            auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
            if (object != nullptr) {
                object->RemoveDeathRecipient(deathRecipient);
            }
        }
    }
}

int32_t AuthEventSubscribeClient::CreatClient(AuthEventCallback callback,
    std::shared_ptr<AuthEventSubscribeClient> &client, bool timeoutAllowFlag)
{
    SGLOGI("CreatClient");
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
    auto serviceCallback = new (std::nothrow) AuthEventCallbackService();
    if (serviceCallback == nullptr) {
        SGLOGE("serviceCallback is null");
        return NULL_OBJECT;
    }
    serviceCallback->RegistCallBack(callback);
    sptr<IRemoteObject> sessionRemote = nullptr;
    int32_t ret = proxy->CreatAuthEventClient(serviceCallback, static_cast<int32_t>(timeoutAllowFlag),
        sessionRemote);
    if (ret != SUCCESS || sessionRemote == nullptr) {
        SGLOGI("CreatAuthEventClient result, ret=%{public}d", ret);
        return ret != SUCCESS ? ret : FAILED;
    }
    client = std::make_shared<AuthEventSubscribeClient>(ConstructTag {});
    client->callback_ = serviceCallback;
    client->timeoutAllowFlag_ = timeoutAllowFlag;
    client->defaultTimeoutMs_ = AUTH_RESULT_TIMEOUT_MS;
    {
        std::lock_guard<ffrt::mutex> memberLock(g_mutex_);
        client->sessionRemote_ = sessionRemote;
    }
    ret = SetDeathRecipient(client, object);
    if (ret != SUCCESS) {
        SGLOGE("SetDeathRecipient fail ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

int32_t AuthEventSubscribeClient::SetDeathRecipient(std::shared_ptr<AuthEventSubscribeClient> client,
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

void AuthEventSubscribeClient::DeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    SGLOGI("DataCollectManagerService died, try to recover AuthEventSubscribeClient state");
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

sptr<IRemoteObject> AuthEventSubscribeClient::ReconnectService()
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

bool AuthEventSubscribeClient::IsDeleted()
{
    std::lock_guard<ffrt::mutex> lock(g_mutex_);
    return deleted_;
}

void AuthEventSubscribeClient::HandleDeath()
{
    std::set<int64_t> events;
    {
        std::lock_guard<ffrt::mutex> lock(g_mutex_);
        events = subscribedEventIds_;
        sessionRemote_ = nullptr; // 服务端已重启，旧会话对象已随进程消亡
    }
    for (int delay : RECONNECT_RETRY_DELAY_SECONDS) {
        ffrt::this_task::sleep_for(std::chrono::seconds(delay));
        if (IsDeleted()) {
            SGLOGI("client deleted, stop reconnect");
            return;
        }
        if (RecoverSession(events)) {
            return;
        }
    }
    SGLOGE("recover AuthEventSubscribeClient fail");
}

bool AuthEventSubscribeClient::RecoverSession(const std::set<int64_t> &events)
{
    sptr<IRemoteObject> object = ReconnectService();
    if (object == nullptr) {
        return false;
    }
    auto proxy = iface_cast<DataCollectManagerIdl>(object);
    if (proxy == nullptr || callback_ == nullptr) {
        SGLOGE("proxy or callback is null");
        return false;
    }
    // 服务端重启后会话丢失，重建会话并获取新的会话对象代理（沿用超时处置策略）
    sptr<IRemoteObject> newSessionRemote = nullptr;
    int32_t ret = proxy->CreatAuthEventClient(callback_,
        static_cast<int32_t>(timeoutAllowFlag_), newSessionRemote);
    if (ret != SUCCESS || newSessionRemote == nullptr) {
        SGLOGE("ReCreatClient fail, ret=%{public}d", ret);
        return false;
    }
    auto sessionProxy = iface_cast<AuthEventSession>(newSessionRemote);
    if (sessionProxy == nullptr) {
        SGLOGE("session proxy is null");
        return false;
    }
    if (!SwitchSessionRemote(newSessionRemote, sessionProxy)) {
        return true; // client 已销毁：新建会话已随之销毁，终止重连
    }
    for (int64_t eventId : events) {
        int32_t code = sessionProxy->Subscribe(eventId);
        if (code != SUCCESS) {
            SGLOGE("ReSubscribe fail, eventId=%{public}lld, ret=%{public}d",
                static_cast<long long>(eventId), code);
        }
    }
    return true;
}

bool AuthEventSubscribeClient::SwitchSessionRemote(const sptr<IRemoteObject> &newSessionRemote,
    const sptr<AuthEventSession> &sessionProxy)
{
    std::lock_guard<ffrt::mutex> lock(g_mutex_);
    if (deleted_) {
        SGLOGI("client deleted during reconnect, discard new session");
        sessionProxy->Destroy();
        return false;
    }
    sessionRemote_ = newSessionRemote;
    return true;
}

int32_t AuthEventSubscribeClient::Subscribe(int64_t eventId)
{
    SGLOGI("SetAuthResult");
    sptr<AuthEventSession> session {};
    {
        std::lock_guard<ffrt::mutex> lock(g_mutex_);
        if (deleted_) {
            SGLOGE("client deleted");
            return BAD_PARAM;
        }
        session = iface_cast<AuthEventSession>(sessionRemote_);
    }
    if (session == nullptr) {
        SGLOGE("session proxy is null");
        return NULL_OBJECT;
    }
    int32_t ret = session->Subscribe(eventId);
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

int32_t AuthEventSubscribeClient::Unsubscribe(int64_t eventId)
{
    SGLOGI("Unsubscribe, eventId=%{public}" PRId64, eventId);
    sptr<AuthEventSession> session {};
    {
        std::lock_guard<ffrt::mutex> lock(g_mutex_);
        if (deleted_) {
            SGLOGE("client deleted");
            return BAD_PARAM;
        }
        session = iface_cast<AuthEventSession>(sessionRemote_);
    }
    if (session == nullptr) {
        SGLOGE("session proxy is null");
        return NULL_OBJECT;
    }
    int32_t ret = session->Unsubscribe(eventId);
    if (ret != SUCCESS) {
        SGLOGI("Unsubscribe result, ret=%{public}d", ret);
        return ret;
    }
    {
        std::lock_guard<ffrt::mutex> lock(g_mutex_);
        subscribedEventIds_.erase(eventId);
    }
    return SUCCESS;
}

int32_t AuthEventSubscribeClient::SetAuthResult(const AuthEvent &event, bool allowFlag)
{
    SGLOGI("SetAuthResult, eventId=%{public}" PRId64 ", seqnum=%{public}" PRId64,
        event.GetEventId(), event.GetSeqnum());
    sptr<AuthEventSession> session{};
    {
        std::lock_guard<ffrt::mutex> lock(g_mutex_);
        if (deleted_) {
            SGLOGE("client deleted");
            return BAD_PARAM;
        }
        session = iface_cast<AuthEventSession>(sessionRemote_);
    }
    if (session == nullptr) {
        SGLOGE("session proxy is null");
        return NULL_OBJECT;
    }
    return session->SetAuthResult(event, allowFlag);
}

void AuthEventSubscribeClient::DeleteClient()
{
    // 注意：禁止在用户回调内部（OnAuthEvent 触发的执行流）调用本接口，
    // 否则会因等待自身持有的 notifyMutex_ 而死锁。
    Release();
}
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
