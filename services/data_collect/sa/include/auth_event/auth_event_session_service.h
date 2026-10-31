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

#ifndef SECURITY_GUARD_AUTH_EVENT_SESSION_SERVICE_H
#define SECURITY_GUARD_AUTH_EVENT_SESSION_SERVICE_H
#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE

#include <cstdint>
#include <set>
#include <string>
#include <unordered_map>

#include "auth_event.h"
#include "auth_event_session_stub.h"
#include "auth_strategy.h"
#include "iremote_object.h"
#include "nocopyable.h"

namespace OHOS::Security::SecurityGuard {
// AuthEvent 会话对象：一个实例 = 一个客户端会话。
// 由 AuthEventSubscribeManager 在 CreatAuthEventClient 时创建，经 [out] 参数把本对象的
// 远端引用下发给客户端；客户端 SDK 持代理直调四方法，binder handle 即会话路由，
// 全链路无 clientId。状态成员即会话状态（非查表所得）；eventIds_ 的读写统一经
// 管理器锁进行（本类自身无锁，IsEventSubscribed 仅允许在管理器锁内调用）。
class AuthEventSessionService : public AuthEventSessionStub, public NoCopyable {
public:
    AuthEventSessionService(pid_t callerPid, int32_t callerUid, AuthStrategy defaultTimeoutStrategy,
        int32_t defaultTimeoutMs, const sptr<IRemoteObject> &callback);
    ~AuthEventSessionService() override = default;

    ErrCode Subscribe(int64_t eventId) override;
    ErrCode Unsubscribe(int64_t eventId) override;
    ErrCode SetAuthResult(const AuthEvent &event, bool allowFlag) override;
    ErrCode Destroy() override;

    sptr<IRemoteObject> GetCallback() const
    {
        return callback_;
    }

    pid_t GetPid() const
    {
        return pid_;
    }

    int32_t GetUid() const
    {
        return uid_;
    }

    // 回填超时处置策略（创建会话时由客户端设置，默认放行）。
    // 本期仅保存不消费：超时判断与处置由另一需求承接，届时按会话读取该策略落值。
    AuthStrategy GetTimeoutStrategy() const
    {
        return defaultTimeoutStrategy_;
    }

    int32_t GetDefaultTimeoutMs() const
    {
        return defaultTimeoutMs_;
    }

    // 客户端唯一标识，用于结果聚合和状态通知
    std::string GetClientId() const
    {
        return clientId_;
    }

    // per-client seqnum 递增（每个客户端接收事件数量的递增数字）
    int64_t GenerateSeqnum()
    {
        return ++seqnumCounter_;
    }

    // 管理器锁内调用：分发时按 eventId 匹配命中会话
    bool IsEventSubscribed(int64_t eventId) const
    {
        return eventIds_.find(eventId) != eventIds_.end();
    }

    // 管理器锁内调用：登记/移除订阅集合
    std::set<int64_t> &GetEventIds()
    {
        return eventIds_;
    }

    // 管理器锁内调用：登记 eventId 所属的 serviceId（阻断服务提供者）。
    // Subscribe 时由 SubscribeAuthEvent 在管理器锁内写入，与 eventIds_ 同步维护。
    void RegisterEventService(int64_t eventId, const std::string &serviceId)
    {
        eventServiceMap_[eventId] = serviceId;
    }

    // 管理器锁内调用：移除 eventId 的 serviceId 映射。Unsubscribe 时同步清理。
    void UnregisterEventService(int64_t eventId)
    {
        eventServiceMap_.erase(eventId);
    }

    // 查询某 eventId 所属 serviceId（CollectClientInfos 按 provider serviceId 过滤时调用）。
    // 返回空串表示该 eventId 未声明 serviceId（旧配置兼容，不应出现在 auth_event 订阅链路）。
    std::string GetServiceIdForEvent(int64_t eventId) const
    {
        auto it = eventServiceMap_.find(eventId);
        return it != eventServiceMap_.end() ? it->second : "";
    }

    // 会话有效性快速检查（权威判定以"是否在管理器会话集合中"为准）
    bool IsValid() const
    {
        return valid_;
    }

    void MarkInvalid()
    {
        valid_ = false;
    }

    void SetDeathRecipient(const sptr<IRemoteObject::DeathRecipient> &recipient)
    {
        deathRecipient_ = recipient;
    }

    sptr<IRemoteObject::DeathRecipient> GetDeathRecipient() const
    {
        return deathRecipient_;
    }

private:
    pid_t pid_ {};
    int32_t uid_ {};
    std::string clientId_ {};
    int64_t seqnumCounter_ {0};  // per-client seqnum 计数器
    AuthStrategy defaultTimeoutStrategy_ {AuthStrategy::ALLOW};
    int32_t defaultTimeoutMs_ {AUTH_RESULT_TIMEOUT_MS};
    sptr<IRemoteObject> callback_ {};
    std::set<int64_t> eventIds_ {};
    std::unordered_map<int64_t, std::string> eventServiceMap_ {};  // eventId → serviceId（阻断服务提供者）
    bool valid_ {true};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ {};
};

// 每会话独立的订阅者死亡观察者：挂在客户端回调对象上，
// 客户端进程死亡时自治清理对应会话（无需按回调反查遍历）。
// wptr 避免与 AuthEventSessionService::deathRecipient_ 形成循环引用
class AuthEventSessionDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit AuthEventSessionDeathRecipient(wptr<AuthEventSessionService> session);
    ~AuthEventSessionDeathRecipient() override = default;
    void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
private:
    wptr<AuthEventSessionService> session_ {};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
#endif // SECURITY_GUARD_AUTH_EVENT_SESSION_SERVICE_H
