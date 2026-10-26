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

#ifndef SECURITY_GUARD_AUTH_EVENT_SUBSCRIBE_MANAGER_H
#define SECURITY_GUARD_AUTH_EVENT_SUBSCRIBE_MANAGER_H
#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE

#include <cstdint>
#include <map>
#include <set>
#include <vector>

#include "ffrt.h"
#include "iremote_object.h"
#include "nocopyable.h"

#include "auth_event.h"
#include "auth_event_session_service.h"
#include "auth_strategy.h"

namespace OHOS::Security::SecurityGuard {
// 客户端配额：一个进程最多 2 个客户端，一个设备最多 16 个客户端
constexpr size_t MAX_AUTH_EVENT_CLIENT_SIZE_ONE_PROCESS = 2;
constexpr size_t MAX_AUTH_EVENT_CLIENT_SIZE = 16;
// AuthEvent 字符串字段长度上限，超限返回 BAD_PARAM
constexpr size_t MAX_AUTH_EVENT_STR_LEN = 4096;
// 单会话订阅 eventId 数量与结果状态表容量上限，超限返回 FILTER_EXCEED_LIMIT
constexpr size_t MAX_AUTH_EVENT_SUBSCRIBE_SIZE = 1024;
constexpr size_t MAX_AUTH_EVENT_RESULT_SIZE = 1024;
// HAP 应用接入所需权限
constexpr const char* AUTH_AUDIT_EVENT_PERMISSION = "ohos.permission.kernel.AUTH_AUDIT_EVENT";

// Client 会话创建参数（控制入参 ≤5）
struct CreateClientParams {
    pid_t callerPid;
    int32_t callerUid;
    int32_t timeoutAllowFlag;
    int32_t defaultTimeoutMs;
    sptr<IRemoteObject> callback;
};

class AuthEventSubscribeManager {
public:
    static AuthEventSubscribeManager& GetInstance();

    // 主接口路径：创建会话对象并经 sessionRemote 下发其远端引用（binder handle 即会话路由）。
    int32_t CreatAuthEventClient(const CreateClientParams &params, sptr<IRemoteObject> &sessionRemote);
    // 会话对象方法路径（AuthEventSessionService 转调，会话有效性以"在会话集合中"为权威判定）
    int32_t SubscribeAuthEvent(AuthEventSessionService *session, int64_t eventId);
    int32_t UnsubscribeAuthEvent(AuthEventSessionService *session, int64_t eventId);
    int32_t SetAuthResult(AuthEventSessionService *session, const AuthEvent &event, int32_t authStrategy);
    int32_t DestroyAuthEventClient(AuthEventSessionService *session);
    // 预留读取口：读取某 eventId 的回填结果
    int32_t GetAuthResult(int64_t eventId, AuthStrategy &authStrategy);
    // 内部事件源注入入口：按各会话已订阅 eventId 分发推送（本期预留）
    void NotifyAuthEvent(const AuthEvent &event);
    // 获取订阅了指定 eventId 的所有有效会话（供 AuthCoordinator 调用）
    std::vector<sptr<AuthEventSessionService>> GetSubscribedSessions(int64_t eventId);
    // 获取全量有效会话快照（供 AuthCoordinator 收集 ClientInfo，锁内快照锁外使用）
    std::vector<sptr<AuthEventSessionService>> GetAllSessions();
    // 订阅者死亡清理入口（AuthEventSessionDeathRecipient 转调）
    void RemoveSession(const sptr<AuthEventSessionService> &session);
    // 双轨接入校验（主接口 CreatAuthEventClient 与 session 四方法前置共用）：
    // native token 查 uid 白名单，HAP token 查 ohos.permission.kernel.AUTH_AUDIT_EVENT
    static int32_t IsCallerAllowed();
    // 允许接入 AuthEvent 框架的 SA 应用（native token）uid 白名单查询。
    // 具体值待产品确认后补入；空清单表示暂拒所有 native token 接入。
    bool IsUidAllowed(int32_t uid) const;

private:
    AuthEventSubscribeManager();
    ~AuthEventSubscribeManager();
    DISALLOW_COPY_AND_MOVE(AuthEventSubscribeManager);

    int32_t CheckQuotaLocked(pid_t callerPid) const;
    std::set<sptr<AuthEventSessionService>>::iterator FindSessionLocked(AuthEventSessionService *session);
    void RemoveSessionLocked(const sptr<AuthEventSessionService> &session);

    // 锁纪律：mutex_ 同时保护会话集合（含各会话 eventIds）与结果表（会话数上限 16，
    // 临界区均为短内存操作，有意不分段锁）。临界区内禁止任何外部调用（binder 死亡通知
    // 注册/注销、IPC 推送、HA 打点），外部动作一律"锁内快照、锁外执行"。
    ffrt::mutex mutex_{};
    std::set<sptr<AuthEventSessionService>> sessions_{};
    std::map<int64_t, AuthStrategy> authResults_{};
    std::vector<int32_t> allowedUids_ {};
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
#endif // SECURITY_GUARD_AUTH_EVENT_SUBSCRIBE_MANAGER_H
