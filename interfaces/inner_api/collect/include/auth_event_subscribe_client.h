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

#ifndef SECURITY_GUARD_AUTH_EVENT_SUBSCRIBE_CLIENT_H
#define SECURITY_GUARD_AUTH_EVENT_SUBSCRIBE_CLIENT_H

// AuthEvent 框架仅特定设备开放：由部件构建开关 security_guard_auth_event_enable 控制，
// 未开启设备上 libsg_collect_sdk 不含本框架符号（调用方在链接期失败）。

#include <cstdint>
#include <functional>
#include <memory>
#include <set>

#include "auth_event.h"
#include "auth_event_callback_service.h"
#include "auth_strategy.h"
#include "iremote_object.h"

namespace OHOS::Security::SecurityGuard {
class AuthEventSession;
using AuthEventCallback = std::function<void(const AuthEvent &event)>;
class AuthEventSubscribeClient {
private:
    struct ConstructTag {};

public:
    // 供 std::make_shared 使用的构造占位：ConstructTag 为私有类型，外部无法构造实参，
    // 保证实例仍只能经 CreatClient 创建
    AuthEventSubscribeClient(ConstructTag tag);
    // 最后一个 shared_ptr 释放时自动断开回调、排空在途 OnAuthEvent 并销毁服务端会话
    ~AuthEventSubscribeClient();
    // 创建会话：服务端创建会话对象并经 [out] 下发远端引用（sessionRemote_），
    // 一个 client 对象 = 一个服务端会话，会话身份由 binder handle 承载，无 clientId。
    // timeoutAllowFlag 随会话保存，供超时处置消费；内部转换为 AuthStrategy
    static int32_t CreatClient(AuthEventCallback callback,
        std::shared_ptr<AuthEventSubscribeClient> &client, bool timeoutAllowFlag = true);
    int32_t Subscribe(int64_t eventId);
    int32_t Unsubscribe(int64_t eventId);
    int32_t SetAuthResult(const AuthEvent &event, bool allowFlag);
    // 断开已注册的回调，并排空 stub 上所有在途的 OnAuthEvent，
    // 随后销毁服务端会话。返回后框架不会再触发用户回调，
    // 此时销毁回调所捕获的状态是安全的。
    // 把 client 作为对象成员的调用方无需显式调用本接口；
    // 最后一个 shared_ptr 释放时析构函数会自动执行该操作。
    void DeleteClient();

private:
    AuthEventSubscribeClient() = default;
    AuthEventSubscribeClient(const AuthEventSubscribeClient&) = delete;
    AuthEventSubscribeClient& operator= (const AuthEventSubscribeClient&) = delete;
    static int32_t SetDeathRecipient(std::shared_ptr<AuthEventSubscribeClient> client,
        const sptr<IRemoteObject> &remote);
    // 断开回调、置销毁标记并销毁服务端会话（DeleteClient 与析构共用路径）
    void Release();
    // 锁外执行跨进程清理：销毁服务端会话并解除 SA 死亡通知
    static void DestroyRemoteObjects(const sptr<IRemoteObject> &sessionRemote,
        const sptr<IRemoteObject::DeathRecipient> &deathRecipient);
    bool IsDeleted();
    // 服务端死亡后的退避重连：重建会话并按快照重订阅，成功或已终止返回 true
    void HandleDeath();
    // 单轮重连尝试：重建会话与订阅；返回 true 表示完成（成功或已销毁终止），false 表示继续重试
    bool RecoverSession(const std::set<int64_t> &events);
    // 锁内写回新会话引用；已销毁时销毁新建会话并返回 false（终止重连）
    bool SwitchSessionRemote(const sptr<IRemoteObject> &newSessionRemote,
        const sptr<AuthEventSession> &sessionProxy);
    sptr<IRemoteObject> ReconnectService();
    class DeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit DeathRecipient(std::weak_ptr<AuthEventSubscribeClient> client) : client_(std::move(client)) {}
        ~DeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    private:
        std::weak_ptr<AuthEventSubscribeClient> client_;
    };
    sptr<AuthEventCallbackService> callback_{};
    sptr<IRemoteObject> sessionRemote_{}; // 服务端下发的会话对象远端引用，CreatClient 时填充
    sptr<IRemoteObject::DeathRecipient> deathRecipient_{};
    std::set<int64_t> subscribedEventIds_{};
    bool timeoutAllowFlag_ {true};
    int32_t defaultTimeoutMs_ {AUTH_RESULT_TIMEOUT_MS};
    bool deleted_ {false}; // 已显式销毁标记：阻止 HandleDeath 自动重建已删除的会话；销毁后各方法返回 BAD_PARAM
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_SUBSCRIBE_CLIENT_H
