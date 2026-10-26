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

#ifndef SECURITY_GUARD_AUTH_PROVIDER_SUBSCRIBE_CLIENT_H
#define SECURITY_GUARD_AUTH_PROVIDER_SUBSCRIBE_CLIENT_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "auth_client_info.h"
#include "auth_event_info.h"
#include "auth_provider_callback_service.h"
#include "auth_result.h"
#include "iremote_object.h"

namespace OHOS::Security::SecurityGuard {
class AuthProviderSession;
using AuthProviderCallback = std::function<void(const std::vector<AuthClientInfo> &clientsInfo)>;
// SA 聚合完成后经回调通知 kit，kit 收到 AuthResult 后触发 Promise 或 std::function
using AuthResultCallback = std::function<void(const AuthResult &result)>;

class AuthProviderSubscribeClient : public std::enable_shared_from_this<AuthProviderSubscribeClient> {
private:
    struct ConstructTag {};

public:
    AuthProviderSubscribeClient(ConstructTag tag);
    ~AuthProviderSubscribeClient();

    static int32_t CreateProvider(AuthProviderCallback callback, const std::string &serviceId,
        std::shared_ptr<AuthProviderSubscribeClient> &provider);
    // 返回码: 请求是否被接受；最终阻断策略经回调返回
    int32_t RequestAuthResult(const AuthEventInfo &event, AuthResultCallback callback);
    void DeleteProvider();

private:
    AuthProviderSubscribeClient() = default;
    AuthProviderSubscribeClient(const AuthProviderSubscribeClient &) = delete;
    AuthProviderSubscribeClient &operator=(const AuthProviderSubscribeClient &) = delete;
    static int32_t SetDeathRecipient(std::shared_ptr<AuthProviderSubscribeClient> provider,
        const sptr<IRemoteObject> &remote);
    void Release();
    static void DestroyRemoteObjects(const sptr<IRemoteObject> &sessionRemote,
        const sptr<IRemoteObject::DeathRecipient> &deathRecipient);
    bool IsDeleted();
    void HandleDeath();
    // 退避重试循环：重新 CreateAuthProvider 注册
    bool RecoverSession(const std::string &serviceId);
    bool SwitchSessionRemote(const sptr<IRemoteObject> &newSessionRemote,
        const sptr<AuthProviderSession> &sessionProxy);
    sptr<IRemoteObject> ReconnectService();

    class DeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit DeathRecipient(std::weak_ptr<AuthProviderSubscribeClient> provider)
            : provider_(std::move(provider)) {}
        ~DeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

    private:
        std::weak_ptr<AuthProviderSubscribeClient> provider_;
    };

    sptr<AuthProviderCallbackService> callback_{};
    sptr<IRemoteObject> sessionRemote_{};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_{};
    std::string serviceId_{};
    std::atomic<bool> deleted_ {false};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_PROVIDER_SUBSCRIBE_CLIENT_H
