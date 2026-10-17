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

#include <chrono>
#include <cinttypes>
#include <future>
#include <set>

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

// SG 进程崩溃后 Provider SDK 退避重连间隔（秒），与 AuthEventSubscribeClient 对齐
constexpr int PROVIDER_RECONNECT_RETRY_DELAY_SECONDS[] = {1, 5, 15, 30, 60, 60, 60, 60, 60};

// 出口错误码拦截: 不在 g_errorStringMap 中的统一归入 AUTH_PROVIDER_INTERNAL_ERROR
int32_t NormalizeErrorCode(int32_t code)
{
    static const std::set<int32_t> validCodes = {
        SUCCESS, NO_PERMISSION, NO_SYSTEMCALL, BAD_PARAM,
        AUTH_PROVIDER_INTERNAL_ERROR, AUTH_PROVIDER_EXCEED_PROCESS_LIMIT,
        AUTH_PROVIDER_EXCEED_GLOBAL_LIMIT, AUTH_REQUEST_EXCEED_LIMIT
    };
    if (validCodes.count(code) > 0) {
        return code;
    }
    return AUTH_PROVIDER_INTERNAL_ERROR;
}
}

AuthProviderSubscribeClient::AuthProviderSubscribeClient(ConstructTag tag) {}

AuthProviderSubscribeClient::~AuthProviderSubscribeClient()
{
    Release();
}

int32_t AuthProviderSubscribeClient::CreateProvider(AuthProviderCallback callback,
    const std::string &serviceId, std::shared_ptr<AuthProviderSubscribeClient> &provider)
{
    SGLOGI("CreateProvider, serviceId=%{public}s", serviceId.c_str());
    
    if (callback == nullptr) {
        SGLOGE("callback is nullptr");
        return BAD_PARAM;
    }
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return AUTH_PROVIDER_INTERNAL_ERROR;
    }
    auto object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    auto proxy = iface_cast<DataCollectManagerIdl>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return AUTH_PROVIDER_INTERNAL_ERROR;
    }
    auto serviceCallback = new (std::nothrow) AuthProviderCallbackService();
    if (serviceCallback == nullptr) {
        SGLOGE("serviceCallback is null");
        return AUTH_PROVIDER_INTERNAL_ERROR;
    }
    serviceCallback->RegistCallBack(callback);
    sptr<IRemoteObject> providerRemote = nullptr;
    int32_t ret = proxy->CreateAuthProvider(serviceCallback, serviceId, providerRemote);
    if (ret != SUCCESS || providerRemote == nullptr) {
        SGLOGI("CreateAuthProvider result, ret=%{public}d", ret);
        return NormalizeErrorCode(ret != SUCCESS ? ret : AUTH_PROVIDER_INTERNAL_ERROR);
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
        return NormalizeErrorCode(ret);
    }
    return SUCCESS;
}

// 返回码: 请求是否被接受；最终阻断策略经回调返回
// kit 侧 promise/future 同步等待 SA 聚合结果，超时 400ms 兜底返回 TIMEOUT（M4+M7）
int32_t AuthProviderSubscribeClient::RequestAuthResult(const AuthEventInfo &event,
    AuthResultCallback callback)
{
    SGLOGI("RequestAuthResult");
    sptr<AuthProviderSession> session {};
    {
        std::lock_guard<ffrt::mutex> lock(g_providerMutex);
        if (deleted_) {
            SGLOGE("provider deleted");
            return AUTH_PROVIDER_INTERNAL_ERROR;
        }
        session = iface_cast<AuthProviderSession>(sessionRemote_);
    }
    if (session == nullptr) {
        SGLOGE("session proxy is null");
        return AUTH_PROVIDER_INTERNAL_ERROR;
    }
    auto callbackService = new (std::nothrow) AuthResultCallbackService();
    if (callbackService == nullptr) {
        SGLOGE("callback service is null");
        return AUTH_PROVIDER_INTERNAL_ERROR;
    }
    // kit 内部用 promise/future 同步转异步：SA 回调写入 promise，kit 阻塞等待
    auto promise = std::make_shared<std::promise<AuthResult>>();
    auto future = promise->get_future();
    callbackService->RegistCallBack([promise](const AuthResult &result) {
        promise->set_value(result);
    });
    int32_t ret = session->RequestAuthResult(event, callbackService->AsObject());
    if (ret != SUCCESS) {
        SGLOGE("SA RequestAuthResult rejected, ret=%{public}d, eventId=%{public}" PRId64,
            ret, event.GetEventId());
        return NormalizeErrorCode(ret);
    }
    SGLOGI("SA RequestAuthResult accepted, eventId=%{public}" PRId64 ", waiting for callback...",
        event.GetEventId());
    // kit 侧 400ms 同步阻塞等待，超时按默认策略返回 TIMEOUT
    auto status = future.wait_for(std::chrono::milliseconds(AUTH_RESULT_TIMEOUT_MS));
    if (status == std::future_status::timeout) {
        SGLOGW("kit wait auth result timeout, return TIMEOUT");
        AuthResult timeoutResult;
        timeoutResult.SetMergedAuthStrategy(AuthStrategy::TIMEOUT);
        callback(timeoutResult);
        return SUCCESS;
    }
    AuthResult authResult = future.get();
    SGLOGI("kit got auth result, mergedStrategy=%{public}d, eventId=%{public}" PRId64,
        static_cast<int32_t>(authResult.GetMergedAuthStrategy()), event.GetEventId());
    callback(authResult);
    return SUCCESS;
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
            return BAD_PARAM;
        }
        if (!remote->AddDeathRecipient(provider->deathRecipient_)) {
            SGLOGE("Failed to add death recipient");
        }
    }
    return SUCCESS;
}

void AuthProviderSubscribeClient::HandleDeath()
{
    SGLOGI("DataCollectManagerService died, try to recover AuthProviderSubscribeClient");
    std::string serviceId;
    {
        std::lock_guard<ffrt::mutex> lock(g_providerMutex);
        serviceId = serviceId_;
    }
    for (int delay : PROVIDER_RECONNECT_RETRY_DELAY_SECONDS) {
        ffrt::this_task::sleep_for(std::chrono::seconds(delay));
        if (IsDeleted()) {
            SGLOGI("provider deleted, stop reconnect");
            return;
        }
        if (RecoverSession(serviceId)) {
            return;
        }
    }
    SGLOGE("recover AuthProviderSubscribeClient fail after retries");
}

bool AuthProviderSubscribeClient::RecoverSession(const std::string &serviceId)
{
    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        SGLOGE("GetSystemAbilityManager error");
        return false;
    }
    sptr<IRemoteObject> object = registry->GetSystemAbility(DATA_COLLECT_MANAGER_SA_ID);
    if (object == nullptr) {
        return false;
    }
    auto proxy = iface_cast<DataCollectManagerIdl>(object);
    if (proxy == nullptr) {
        SGLOGE("proxy is null");
        return false;
    }
    // 锁内拷贝 callback_ 副本并检查 deleted_，避免与 Release() 并发读写 sptr 引用计数错乱
    sptr<AuthProviderCallbackService> callback;
    {
        std::lock_guard<ffrt::mutex> lock(g_providerMutex);
        if (deleted_) {
            SGLOGI("provider deleted during reconnect, discard");
            return false;
        }
        callback = callback_;
    }
    if (callback == nullptr) {
        SGLOGE("callback is null");
        return false;
    }
    // 重新向 SA 注册：SA 侧 CreateAuthProvider 完成后会 NotifyClientStatusChanged 下发全量客户端列表
    sptr<IRemoteObject> newRemote = nullptr;
    int32_t ret = proxy->CreateAuthProvider(callback, serviceId, newRemote);
    if (ret != SUCCESS || newRemote == nullptr) {
        SGLOGE("ReCreateProvider fail, ret=%{public}d", ret);
        return false;
    }
    {
        std::lock_guard<ffrt::mutex> lock(g_providerMutex);
        if (deleted_) {
            SGLOGI("provider deleted during reconnect, discard");
            return false;
        }
        sessionRemote_ = newRemote;
    }
    // 重新挂死亡监听到新 SA 对象
    SetDeathRecipient(shared_from_this(), object);
    SGLOGI("recover AuthProvider success, SA 下发全量客户端列表由 NotifyClientStatusChanged 触发");
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
    sptr<IRemoteObject> object = remote.promote();
    if (object != nullptr) {
        object->RemoveDeathRecipient(this);
    }
    // 避免阻塞 binder 线程，异步执行退避重连
    ffrt::submit([provider]() { provider->HandleDeath(); });
}
} // namespace OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE

#ifndef SECURITY_GUARD_AUTH_EVENT_ENABLE
namespace OHOS::Security::SecurityGuard {
int32_t AuthProviderSubscribeClient::CreateProvider(AuthProviderCallback callback,
    const std::string &serviceId, std::shared_ptr<AuthProviderSubscribeClient> &provider)
{
    (void)callback;
    (void)serviceId;
    (void)provider;
    return API_SUPPORT_ERROR;
}

int32_t AuthProviderSubscribeClient::RequestAuthResult(const AuthEventInfo &event,
    AuthResultCallback callback)
{
    (void)event;
    (void)callback;
    return API_SUPPORT_ERROR;
}

void AuthProviderSubscribeClient::DeleteProvider()
{
}

AuthProviderSubscribeClient::AuthProviderSubscribeClient(ConstructTag tag) {}
AuthProviderSubscribeClient::~AuthProviderSubscribeClient() {}
} // namespace OHOS::Security::SecurityGuard
#endif // !SECURITY_GUARD_AUTH_EVENT_ENABLE
