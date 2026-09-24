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

#include "auth_provider_subscribe_client.h"

#include <cinttypes>

#include "auth_result_callback_service.h"
#include "data_collect_manager.h"
#include "data_collect_manager_idl.h"
#include "auth_provider_session.h"
#include "ffrt.h"
#include "i_auth_provider_callback.h"
#include "ipc_skeleton.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
namespace OHOS::Security::SecurityGuard {
namespace {
ffrt::mutex g_providerMutex {};
}

AuthProviderSubscribeClient::AuthProviderSubscribeClient(ConstructTag tag) {}

AuthProviderSubscribeClient::~AuthProviderSubscribeClient()
{
    Release();
}

int32_t AuthProviderSubscribeClient::CreateProvider(AuthProviderCallback callback,
    const std::string &serviceId, std::shared_ptr<AuthProviderSubscribeClient> &provider)
{
    SGLOGI("enter");
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
    auto serviceCallback = new (std::nothrow) AuthProviderCallbackService();
    if (serviceCallback == nullptr) {
        SGLOGE("serviceCallback is null");
        return NULL_OBJECT;
    }
    serviceCallback->RegistCallBack(callback);
    sptr<IRemoteObject> providerRemote = nullptr;
    int32_t ret = proxy->CreateAuthProvider(serviceCallback, serviceId, providerRemote);
    if (ret != SUCCESS || providerRemote == nullptr) {
        SGLOGI("CreateAuthProvider result, ret=%{public}d", ret);
        return ret != SUCCESS ? ret : FAILED;
    }
    provider = std::make_shared<AuthProviderSubscribeClient>(ConstructTag {});
    provider->callback_ = serviceCallback;
    provider->serviceId_ = serviceId;
    {
        std::lock_guard<ffrt::mutex> lock(g_providerMutex);
        provider->sessionRemote_ = providerRemote;
    }
    ret = SetDeathRecipient(provider, object);
    if (ret != SUCCESS) {
        SGLOGE("SetDeathRecipient fail ret=%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

// 返回码: 请求是否被接受；最终阻断策略经回调返回
// SDK 内部创建 AuthResultCallbackService 包装 std::function，作为 IRemoteObject 传给 SA
int32_t AuthProviderSubscribeClient::RequestAuthResult(const AuthEventInfo &event,
    AuthResultCallback callback)
{
    SGLOGI("enter");
    sptr<AuthProviderSession> session {};
    {
        std::lock_guard<ffrt::mutex> lock(g_providerMutex);
        if (deleted_) {
            SGLOGE("provider deleted");
            return BAD_PARAM;
        }
        session = iface_cast<AuthProviderSession>(sessionRemote_);
    }
    if (session == nullptr) {
        SGLOGE("session proxy is null");
        return NULL_OBJECT;
    }
    // 创建回调 stub，包装 std::function → SA 聚合完成后经 IPC 回调 → 触发 std::function
    auto callbackService = new (std::nothrow) AuthResultCallbackService();
    if (callbackService == nullptr) {
        SGLOGE("callback service is null");
        return FAILED;
    }
    callbackService->RegistCallBack(callback);
    return session->RequestAuthResult(event, callbackService->AsObject());
}

void AuthProviderSubscribeClient::DeleteProvider()
{
    Release();
}

void AuthProviderSubscribeClient::Release()
{
    bool expected = false;
    if (!deleted_.compare_exchange_strong(expected, true)) {
        return;
    }
    sptr<AuthProviderCallbackService> callback;
    sptr<IRemoteObject> sessionRemote;
    sptr<IRemoteObject::DeathRecipient> deathRecipient;
    {
        std::lock_guard<ffrt::mutex> lock(g_providerMutex);
        callback = callback_;
        sessionRemote = sessionRemote_;
        deathRecipient = deathRecipient_;
    }
    if (callback != nullptr) {
        callback->ClearCallBack();
    }
    sptr<AuthProviderSession> session = iface_cast<AuthProviderSession>(sessionRemote);
    if (session != nullptr) {
        session->Destroy();
    }
    DestroyRemoteObjects(sessionRemote, deathRecipient);
    {
        std::lock_guard<ffrt::mutex> lock(g_providerMutex);
        callback_ = nullptr;
        sessionRemote_ = nullptr;
        deathRecipient_ = nullptr;
    }
}

void AuthProviderSubscribeClient::DestroyRemoteObjects(const sptr<IRemoteObject> &sessionRemote,
    const sptr<IRemoteObject::DeathRecipient> &deathRecipient)
{
    if (sessionRemote != nullptr && deathRecipient != nullptr) {
        sessionRemote->RemoveDeathRecipient(deathRecipient);
    }
}

bool AuthProviderSubscribeClient::IsDeleted()
{
    return deleted_.load();
}

int32_t AuthProviderSubscribeClient::SetDeathRecipient(std::shared_ptr<AuthProviderSubscribeClient> provider,
    const sptr<IRemoteObject> &remote)
{
    if (provider->deathRecipient_ == nullptr) {
        provider->deathRecipient_ = new (std::nothrow) DeathRecipient(provider);
        if (provider->deathRecipient_ == nullptr) {
            SGLOGE("deathRecipient_ is nullptr.");
            return NULL_OBJECT;
        }
        if (!remote->AddDeathRecipient(provider->deathRecipient_)) {
            SGLOGE("Failed to add death recipient");
        }
    }
    return SUCCESS;
}

void AuthProviderSubscribeClient::HandleDeath()
{
    SGLOGI("DataCollectManagerService died, try to recover AuthProviderSubscribeClient state");
    sptr<IRemoteObject> newRemote = ReconnectService();
    if (newRemote == nullptr) {
        SGLOGE("reconnect fail");
        return;
    }
    sptr<AuthProviderSession> newSession = iface_cast<AuthProviderSession>(newRemote);
    if (newSession == nullptr) {
        SGLOGE("new session proxy is null");
        return;
    }
    if (!SwitchSessionRemote(newRemote, newSession)) {
        newSession->Destroy();
    }
}

bool AuthProviderSubscribeClient::RecoverSession()
{
    return true;
}

sptr<IRemoteObject> AuthProviderSubscribeClient::ReconnectService()
{
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return nullptr;
    }
    return registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
}

bool AuthProviderSubscribeClient::SwitchSessionRemote(const sptr<IRemoteObject> &newSessionRemote,
    const sptr<AuthProviderSession> &sessionProxy)
{
    std::lock_guard<ffrt::mutex> lock(g_providerMutex);
    if (deleted_) {
        return false;
    }
    sessionRemote_ = newSessionRemote;
    return true;
}

void AuthProviderSubscribeClient::DeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    SGLOGI("DataCollectManagerService died, try to recover AuthProviderSubscribeClient state");
    auto provider = provider_.lock();
    if (provider == nullptr) {
        return;
    }
    provider->HandleDeath();
}
} // namespace OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
