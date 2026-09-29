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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "security_guard_define.h"
#include "system_ability_definition.h"
#define private public
#define protected public
#include "accesstoken_kit.h"
#include "acquire_data_subscribe_manager.h"
#include "auth_event_session_service.h"
#include "auth_event_subscribe_manager.h"
#include "auth_strategy.h"
#include "config_data_manager.h"
#include "data_collect_manager_service.h"
#include "i_auth_event_callback.h"
#include "security_event_query_callback_proxy.h"
#undef private
#undef protected

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security;
using namespace OHOS::Security::SecurityGuard;

namespace {
constexpr int32_t TEST_DEFAULT_TIMEOUT_MS = 400;

class AuthEventSubscribeManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        auto &manager = AuthEventSubscribeManager::GetInstance();
        std::lock_guard<ffrt::mutex> lock(manager.mutex_);
        manager.sessions_.clear();
        manager.authResults_.clear();
        manager.allowedUids_.clear();
    }
    void TearDown() override {}
};

sptr<MockRemoteObject> CreateRemoteObject()
{
    auto obj = sptr<MockRemoteObject>(new (std::nothrow) MockRemoteObject());
    if (obj != nullptr) {
        ON_CALL(*obj, AddDeathRecipient(_)).WillByDefault(Return(true));
        ON_CALL(*obj, RemoveDeathRecipient(_)).WillByDefault(Return(true));
    }
    return obj;
}

// 经管理器创建会话并返回会话对象裸指针（管理器会话集合持有强引用，测试期内有效）
AuthEventSessionService *CreateManagedSession(pid_t pid, int32_t uid, AuthStrategy timeoutStrategy,
    const sptr<IRemoteObject> &cb)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    sptr<IRemoteObject> sessionRemote = nullptr;
    CreateClientParams params;
    params.callerPid = pid;
    params.callerUid = uid;
    params.defaultTimeoutStrategy = timeoutStrategy;
    params.defaultTimeoutMs = TEST_DEFAULT_TIMEOUT_MS;
    params.callback = cb;
    if (manager.CreatAuthEventClient(params, sessionRemote) != SUCCESS) {
        return nullptr;
    }
    return static_cast<AuthEventSessionService *>(sessionRemote.GetRefPtr());
}
}

HWTEST_F(AuthEventSubscribeManagerTest, IsUidAllowed001, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    // 空清单占位：具体 uid 值待产品提供后补入，补值前所有 native uid 均被拒绝
    EXPECT_FALSE(manager.IsUidAllowed(0));
    EXPECT_FALSE(manager.IsUidAllowed(getuid()));
    // 补值后即生效
    manager.allowedUids_ = {12345};
    EXPECT_TRUE(manager.IsUidAllowed(12345));
    EXPECT_FALSE(manager.IsUidAllowed(12346));
    manager.allowedUids_.clear();
}

HWTEST_F(AuthEventSubscribeManagerTest, DualTrackCheck001, TestSize.Level0)
{
    // native token + uid 不在清单 -> NO_PERMISSION
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenTypeFlag)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_NATIVE));
    DataCollectManagerService service(SecurityGuard::DATA_COLLECT_MANAGER_SA_ID, true);
    sptr<IRemoteObject> sessionRemote = nullptr;
    int32_t result = service.CreatAuthEventClient(CreateRemoteObject(),
        static_cast<int32_t>(AuthStrategy::ALLOW), TEST_DEFAULT_TIMEOUT_MS, sessionRemote);
    EXPECT_EQ(result, NO_PERMISSION);
    EXPECT_EQ(sessionRemote, nullptr);
}

HWTEST_F(AuthEventSubscribeManagerTest, DualTrackCheck002, TestSize.Level0)
{
    // native token + uid 在清单 -> SUCCESS 且下发非空会话对象
    auto &manager = AuthEventSubscribeManager::GetInstance();
    manager.allowedUids_ = {getuid()};
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenTypeFlag)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_NATIVE));
    DataCollectManagerService service(SecurityGuard::DATA_COLLECT_MANAGER_SA_ID, true);
    sptr<IRemoteObject> sessionRemote = nullptr;
    int32_t result = service.CreatAuthEventClient(CreateRemoteObject(),
        static_cast<int32_t>(AuthStrategy::ALLOW), TEST_DEFAULT_TIMEOUT_MS, sessionRemote);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_NE(sessionRemote, nullptr);
    manager.allowedUids_.clear();
}

HWTEST_F(AuthEventSubscribeManagerTest, DualTrackCheck003, TestSize.Level0)
{
    // HAP token + 权限 GRANTED -> SUCCESS 且下发非空会话对象
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenTypeFlag)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    DataCollectManagerService service(SecurityGuard::DATA_COLLECT_MANAGER_SA_ID, true);
    sptr<IRemoteObject> sessionRemote = nullptr;
    int32_t result = service.CreatAuthEventClient(CreateRemoteObject(),
        static_cast<int32_t>(AuthStrategy::ALLOW), TEST_DEFAULT_TIMEOUT_MS, sessionRemote);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_NE(sessionRemote, nullptr);
}

HWTEST_F(AuthEventSubscribeManagerTest, DualTrackCheck004, TestSize.Level0)
{
    // HAP token + 权限 DENIED -> NO_PERMISSION
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenTypeFlag)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(SecurityGuard::DATA_COLLECT_MANAGER_SA_ID, true);
    sptr<IRemoteObject> sessionRemote = nullptr;
    int32_t result = service.CreatAuthEventClient(CreateRemoteObject(),
        static_cast<int32_t>(AuthStrategy::ALLOW), TEST_DEFAULT_TIMEOUT_MS, sessionRemote);
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(AuthEventSubscribeManagerTest, DualTrackCheck005, TestSize.Level0)
{
    // 非 native/HAP token -> NO_PERMISSION
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenTypeFlag)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_INVALID));
    DataCollectManagerService service(SecurityGuard::DATA_COLLECT_MANAGER_SA_ID, true);
    sptr<IRemoteObject> sessionRemote = nullptr;
    int32_t result = service.CreatAuthEventClient(CreateRemoteObject(),
        static_cast<int32_t>(AuthStrategy::ALLOW), TEST_DEFAULT_TIMEOUT_MS, sessionRemote);
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(AuthEventSubscribeManagerTest, SetAuthResultPermission001, TestSize.Level0)
{
    // 会话回填权限：先以 GRANTED 建立会话，再切换 DENIED -> NO_PERMISSION
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenTypeFlag)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    DataCollectManagerService service(SecurityGuard::DATA_COLLECT_MANAGER_SA_ID, true);
    sptr<IRemoteObject> sessionRemote = nullptr;
    ASSERT_EQ(service.CreatAuthEventClient(CreateRemoteObject(),
        static_cast<int32_t>(AuthStrategy::ALLOW), TEST_DEFAULT_TIMEOUT_MS, sessionRemote), SUCCESS);
    auto *session = static_cast<AuthEventSessionService *>(sessionRemote.GetRefPtr());
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    AuthEvent event(4001, "content", "metadata");
    EXPECT_EQ(session->SetAuthResult(event, AuthStrategy::ALLOW), NO_PERMISSION);
}

HWTEST_F(AuthEventSubscribeManagerTest, SetAuthResultPermission002, TestSize.Level0)
{
    // 会话回填权限：HAP + GRANTED -> SUCCESS 且状态表落值
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenTypeFlag)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    DataCollectManagerService service(SecurityGuard::DATA_COLLECT_MANAGER_SA_ID, true);
    sptr<IRemoteObject> sessionRemote = nullptr;
    ASSERT_EQ(service.CreatAuthEventClient(CreateRemoteObject(),
        static_cast<int32_t>(AuthStrategy::ALLOW), TEST_DEFAULT_TIMEOUT_MS, sessionRemote), SUCCESS);
    auto *session = static_cast<AuthEventSessionService *>(sessionRemote.GetRefPtr());
    AuthEvent event(4002, "content", "metadata");
    EXPECT_EQ(session->SetAuthResult(event, AuthStrategy::ALLOW), SUCCESS);
    AuthStrategy authStrategy = AuthStrategy::ALLOW;
    EXPECT_EQ(AuthEventSubscribeManager::GetInstance().GetAuthResult(4002, authStrategy), SUCCESS);
    EXPECT_TRUE(allowFlag);
}

HWTEST_F(AuthEventSubscribeManagerTest, SessionApiPermission001, TestSize.Level0)
{
    // 会话方法前置权限校验：无权限调用方（HAP+DENIED）在会话校验前即被拦截 -> NO_PERMISSION
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenTypeFlag)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    auto *session = CreateManagedSession(getpid(), getuid(), AuthStrategy::ALLOW, CreateRemoteObject());
    ASSERT_NE(nullptr, session);
    AuthEvent event(5001, "content", "metadata");
    EXPECT_EQ(session->Subscribe(5001), NO_PERMISSION);
    EXPECT_EQ(session->Unsubscribe(5001), NO_PERMISSION);
    EXPECT_EQ(session->SetAuthResult(event, AuthStrategy::ALLOW), NO_PERMISSION);
    EXPECT_EQ(session->Destroy(), NO_PERMISSION);
}

HWTEST_F(AuthEventSubscribeManagerTest, SessionApiPermission002, TestSize.Level0)
{
    // 有权限调用方（HAP+GRANTED）通过权限校验，进入会话校验（已销毁会话 -> BAD_PARAM）
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenTypeFlag)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    auto *session = CreateManagedSession(getpid(), getuid(), AuthStrategy::ALLOW, CreateRemoteObject());
    ASSERT_NE(nullptr, session);
    ASSERT_EQ(session->Destroy(), SUCCESS);
    AuthEvent event(5002, "content", "metadata");
    EXPECT_EQ(session->Subscribe(5002), BAD_PARAM);
    EXPECT_EQ(session->Unsubscribe(5002), BAD_PARAM);
    EXPECT_EQ(session->SetAuthResult(event, AuthStrategy::ALLOW), BAD_PARAM);
}

HWTEST_F(AuthEventSubscribeManagerTest, SubscribeEventIdNotInConfig001, TestSize.Level0)
{
    // 订阅的 eventId 必须在事件配置中（GetEventConfig 未命中 -> BAD_PARAM）
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenTypeFlag)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &config) {
            if (eventId == 6001) { // 仅 6001 在配置中
                config.eventId = eventId;
                return true;
            }
            return false;
        });
    auto *session = CreateManagedSession(getpid(), getuid(), AuthStrategy::ALLOW, CreateRemoteObject());
    ASSERT_NE(nullptr, session);
    // 配置中的 eventId 通过配置校验并登记成功
    EXPECT_EQ(session->Subscribe(6001), SUCCESS);
    // 不在配置中的 eventId -> BAD_PARAM（配置校验前置拦截）
    EXPECT_EQ(session->Subscribe(6002), BAD_PARAM);
    // 退订不做配置校验（配置可能在运行中被移除，退订按会话数据操作）
    EXPECT_EQ(session->Unsubscribe(6002), SUCCESS);
}

HWTEST_F(AuthEventSubscribeManagerTest, CreatAuthEventClient001, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    sptr<IRemoteObject> cb = CreateRemoteObject();
    sptr<IRemoteObject> sessionRemote = nullptr;
    // 正常创建：下发非空会话对象
    EXPECT_EQ(manager.CreatAuthEventClient(9001, 9001 + 100, true, cb, sessionRemote), SUCCESS);
    EXPECT_NE(sessionRemote, nullptr);
    // 同一 cb 重复创建 -> BAD_PARAM
    sptr<IRemoteObject> sessionRemote2 = nullptr;
    EXPECT_EQ(manager.CreatAuthEventClient(9001, 9001 + 100, true, cb, sessionRemote2), BAD_PARAM);
    // 空回调 -> NULL_OBJECT
    sptr<IRemoteObject> sessionRemote3 = nullptr;
    EXPECT_EQ(manager.CreatAuthEventClient(9001, 9001 + 100, true, nullptr, sessionRemote3), NULL_OBJECT);
}

HWTEST_F(AuthEventSubscribeManagerTest, TimeoutPolicyStorage001, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    // 超时处置策略随会话保存（本需求仅保存不消费，超时判断属另一需求）：
    // 创建时设置阻断(false) -> 会话读取为 false；默认放行(true) -> 读取为 true
    auto *blockSession = CreateManagedSession(9801, 9801 + 100, AuthStrategy::DENY, CreateRemoteObject());
    ASSERT_NE(nullptr, blockSession);
    EXPECT_FALSE(blockSession->GetTimeoutAllowFlag());
    auto *allowSession = CreateManagedSession(9802, 9802 + 100, AuthStrategy::ALLOW, CreateRemoteObject());
    ASSERT_NE(nullptr, allowSession);
    EXPECT_TRUE(allowSession->GetTimeoutAllowFlag());
}

HWTEST_F(AuthEventSubscribeManagerTest, QuotaLimit001, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    sptr<IRemoteObject> sessionRemote = nullptr;
    EXPECT_EQ(manager.CreatAuthEventClient(9101, 9101 + 100, true, CreateRemoteObject(), sessionRemote), SUCCESS);
    EXPECT_EQ(manager.CreatAuthEventClient(9101, 9101 + 100, true, CreateRemoteObject(), sessionRemote), SUCCESS);
    // 同一进程第 3 个客户端
    EXPECT_EQ(manager.CreatAuthEventClient(9101, 9101 + 100, true, CreateRemoteObject(), sessionRemote),
        CLIENT_EXCEED_PROCESS_LIMIT);
    // 其他进程不受影响
    EXPECT_EQ(manager.CreatAuthEventClient(9102, 9102 + 100, true, CreateRemoteObject(), sessionRemote), SUCCESS);
}

HWTEST_F(AuthEventSubscribeManagerTest, QuotaLimit002, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    sptr<IRemoteObject> sessionRemote = nullptr;
    for (pid_t pid = 9200; pid < 9208; pid++) {
        EXPECT_EQ(manager.CreatAuthEventClient(pid, pid + 100, true, CreateRemoteObject(), sessionRemote), SUCCESS);
        EXPECT_EQ(manager.CreatAuthEventClient(pid, pid + 100, true, CreateRemoteObject(), sessionRemote), SUCCESS);
    }
    // 会话集合已满 16，新进程创建 -> GLOBAL_LIMIT
    EXPECT_EQ(manager.CreatAuthEventClient(9300, 9300 + 100, true, CreateRemoteObject(), sessionRemote),
        CLIENT_EXCEED_GLOBAL_LIMIT);
    // 销毁后可重新创建
    auto *session = CreateManagedSession(9207, 9207 + 100, AuthStrategy::ALLOW, CreateRemoteObject());
    ASSERT_NE(nullptr, session);
    EXPECT_EQ(manager.DestroyAuthEventClient(session), SUCCESS);
    EXPECT_EQ(manager.CreatAuthEventClient(9300, 9300 + 100, true, CreateRemoteObject(), sessionRemote), SUCCESS);
}

HWTEST_F(AuthEventSubscribeManagerTest, SubscribeAndNotify001, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    sptr<MockRemoteObject> obj = CreateRemoteObject();
    EXPECT_CALL(*obj, SendRequest(IAuthEventCallback::CMD_ON_AUTH_EVENT, _, _, _)).Times(1);
    auto *session = CreateManagedSession(9401, 9401 + 100, true, obj);
    ASSERT_NE(nullptr, session);
    ASSERT_EQ(manager.SubscribeAuthEvent(session, 1001), SUCCESS);
    // 重复订阅幂等
    EXPECT_EQ(manager.SubscribeAuthEvent(session, 1001), SUCCESS);
    AuthEvent event(1001);
    manager.NotifyAuthEvent(event);
    // 未订阅的 eventId 不推送
    AuthEvent otherEvent(2002);
    manager.NotifyAuthEvent(otherEvent);
    testing::Mock::VerifyAndClearExpectations(obj.GetRefPtr());
}

HWTEST_F(AuthEventSubscribeManagerTest, UnsubscribeAndNotify002, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    sptr<MockRemoteObject> obj = CreateRemoteObject();
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(0);
    auto *session = CreateManagedSession(9402, 9402 + 100, true, obj);
    ASSERT_NE(nullptr, session);
    ASSERT_EQ(manager.SubscribeAuthEvent(session, 1002), SUCCESS);
    EXPECT_EQ(manager.UnsubscribeAuthEvent(session, 1002), SUCCESS);
    AuthEvent event(1002);
    manager.NotifyAuthEvent(event);
    testing::Mock::VerifyAndClearExpectations(obj.GetRefPtr());
}

HWTEST_F(AuthEventSubscribeManagerTest, UnsubscribeNotSubscribed003, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    auto *session = CreateManagedSession(9403, 9403 + 100, true, CreateRemoteObject());
    ASSERT_NE(nullptr, session);
    // 退订未订阅的 eventId -> 幂等 SUCCESS
    EXPECT_EQ(manager.UnsubscribeAuthEvent(session, 1003), SUCCESS);
}

HWTEST_F(AuthEventSubscribeManagerTest, InvalidSession004, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    auto *session = CreateManagedSession(9404, 9404 + 100, true, CreateRemoteObject());
    ASSERT_NE(nullptr, session);
    ASSERT_EQ(manager.DestroyAuthEventClient(session), SUCCESS);
    // 已销毁会话（不在会话集合）-> BAD_PARAM
    EXPECT_EQ(manager.SubscribeAuthEvent(session, 1004), BAD_PARAM);
    EXPECT_EQ(manager.UnsubscribeAuthEvent(session, 1004), BAD_PARAM);
    AuthEvent event(1004, "content", "metadata");
    EXPECT_EQ(manager.SetAuthResult(session, event, AuthStrategy::ALLOW), BAD_PARAM);
}

HWTEST_F(AuthEventSubscribeManagerTest, PidBound005, TestSize.Level0)
{
    // 会话方法按调用方进程绑定：其他进程的会话对象（pid 不匹配）无法操作
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenTypeFlag)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    auto *session = CreateManagedSession(9999, 9999 + 100, true, CreateRemoteObject());
    ASSERT_NE(nullptr, session);
    EXPECT_EQ(session->Subscribe(1006), BAD_PARAM);
    EXPECT_EQ(session->Unsubscribe(1006), BAD_PARAM);
    AuthEvent event(1006, "content", "metadata");
    EXPECT_EQ(session->SetAuthResult(event, AuthStrategy::ALLOW), BAD_PARAM);
    EXPECT_EQ(session->Destroy(), BAD_PARAM);
    // 归属进程（本进程）的会话操作正常
    auto *ownSession = CreateManagedSession(getpid(), getuid(), AuthStrategy::ALLOW, CreateRemoteObject());
    ASSERT_NE(nullptr, ownSession);
    EXPECT_EQ(ownSession->Subscribe(1006), SUCCESS);
    EXPECT_EQ(ownSession->Destroy(), SUCCESS);
}

HWTEST_F(AuthEventSubscribeManagerTest, DestroySemantics006, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenTypeFlag)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    auto *session = CreateManagedSession(getpid(), getuid(), AuthStrategy::ALLOW, CreateRemoteObject());
    ASSERT_NE(nullptr, session);
    ASSERT_EQ(session->Destroy(), SUCCESS);
    // 销毁后再订阅 -> BAD_PARAM（会话已置无效）
    EXPECT_EQ(session->Subscribe(1005), BAD_PARAM);
    // 重复销毁 -> 幂等 SUCCESS（"确保销毁"语义）
    EXPECT_EQ(session->Destroy(), SUCCESS);
}

HWTEST_F(AuthEventSubscribeManagerTest, SetAuthResult001, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    AuthEvent event(3001, "content", "metadata");
    // 已销毁会话回填 -> BAD_PARAM
    auto *stale = CreateManagedSession(9501, 9501 + 100, true, CreateRemoteObject());
    ASSERT_NE(nullptr, stale);
    ASSERT_EQ(manager.DestroyAuthEventClient(stale), SUCCESS);
    EXPECT_EQ(manager.SetAuthResult(stale, event, AuthStrategy::ALLOW), BAD_PARAM);

    auto *session = CreateManagedSession(9502, 9502 + 100, true, CreateRemoteObject());
    ASSERT_NE(nullptr, session);
    EXPECT_EQ(manager.SetAuthResult(session, event, AuthStrategy::ALLOW), SUCCESS);
    AuthStrategy authStrategy = AuthStrategy::ALLOW;
    EXPECT_EQ(manager.GetAuthResult(3001, allowFlag), SUCCESS);
    EXPECT_TRUE(allowFlag);
    // 覆盖更新
    EXPECT_EQ(manager.SetAuthResult(session, event, AuthStrategy::DENY), SUCCESS);
    EXPECT_EQ(manager.GetAuthResult(3001, allowFlag), SUCCESS);
    EXPECT_FALSE(allowFlag);
    // 未设置过的 eventId
    EXPECT_EQ(manager.GetAuthResult(9999, allowFlag), NOT_FOUND);
}

HWTEST_F(AuthEventSubscribeManagerTest, SetAuthResultTooLong002, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    auto *session = CreateManagedSession(9503, 9503 + 100, true, CreateRemoteObject());
    ASSERT_NE(nullptr, session);
    std::string tooLong(MAX_AUTH_EVENT_STR_LEN + 1, 'a');
    AuthEvent longContent(3002, tooLong, "");
    EXPECT_EQ(manager.SetAuthResult(session, longContent, AuthStrategy::ALLOW), BAD_PARAM);
    AuthEvent longMetadata(3003, "", tooLong);
    EXPECT_EQ(manager.SetAuthResult(session, longMetadata, AuthStrategy::ALLOW), BAD_PARAM);
}

HWTEST_F(AuthEventSubscribeManagerTest, CollectionSizeLimit001, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    auto *session = CreateManagedSession(9510, 9510 + 100, true, CreateRemoteObject());
    ASSERT_NE(nullptr, session);
    for (int64_t eventId = 1; eventId <= static_cast<int64_t>(MAX_AUTH_EVENT_SUBSCRIBE_SIZE); eventId++) {
        ASSERT_EQ(manager.SubscribeAuthEvent(session, eventId), SUCCESS);
    }
    // 单会话订阅数超限
    EXPECT_EQ(manager.SubscribeAuthEvent(session, MAX_AUTH_EVENT_SUBSCRIBE_SIZE + 1), FILTER_EXCEED_LIMIT);
}

HWTEST_F(AuthEventSubscribeManagerTest, CollectionSizeLimit002, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    auto *session = CreateManagedSession(9511, 9511 + 100, true, CreateRemoteObject());
    ASSERT_NE(nullptr, session);
    for (int64_t eventId = 1; eventId <= static_cast<int64_t>(MAX_AUTH_EVENT_RESULT_SIZE); eventId++) {
        AuthEvent event(eventId);
        ASSERT_EQ(manager.SetAuthResult(session, event, AuthStrategy::ALLOW), SUCCESS);
    }
    // 结果状态表容量超限
    AuthEvent overflow(MAX_AUTH_EVENT_RESULT_SIZE + 1);
    EXPECT_EQ(manager.SetAuthResult(session, overflow, AuthStrategy::ALLOW), FILTER_EXCEED_LIMIT);
}

HWTEST_F(AuthEventSubscribeManagerTest, SubscriberDied007, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    sptr<MockRemoteObject> obj = CreateRemoteObject();
    EXPECT_CALL(*obj, SendRequest(_, _, _, _)).Times(0);
    auto *session = CreateManagedSession(9601, 9601 + 100, true, obj);
    ASSERT_NE(nullptr, session);
    ASSERT_EQ(manager.SubscribeAuthEvent(session, 1007), SUCCESS);
    // 经真实 per-session DeathRecipient 回调链路触发清理
    auto recipient = session->GetDeathRecipient();
    ASSERT_NE(recipient, nullptr);
    recipient->OnRemoteDied(obj);
    // 会话移除后再订阅 -> BAD_PARAM
    EXPECT_EQ(manager.SubscribeAuthEvent(session, 1007), BAD_PARAM);
    AuthEvent event(1007);
    manager.NotifyAuthEvent(event);
    testing::Mock::VerifyAndClearExpectations(obj.GetRefPtr());
}

HWTEST_F(AuthEventSubscribeManagerTest, AuthBlockResultReport001, TestSize.Level0)
{
    auto &manager = AuthEventSubscribeManager::GetInstance();
    // 阻断结果回填：打点路径在无 HA 环境下仅告警，不影响返回值
    auto *session = CreateManagedSession(9703, 9703 + 100, true, CreateRemoteObject());
    ASSERT_NE(nullptr, session);
    AuthEvent event(1104, "content", "metadata");
    EXPECT_EQ(manager.SetAuthResult(session, event, AuthStrategy::DENY), SUCCESS);
    bool allowFlag = true;
    EXPECT_EQ(manager.GetAuthResult(1104, allowFlag), SUCCESS);
    EXPECT_FALSE(allowFlag);
}

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
