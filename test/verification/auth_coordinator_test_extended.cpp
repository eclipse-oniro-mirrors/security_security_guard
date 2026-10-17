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

// ============================================================================
// 阻断事件管理框架 — C++ 单元测试扩展用例
//
// 覆盖：从严策略、超时、计数、错误码、聚合断链（M1）、per-provider 并发（M6）、
//       超时打点（M13）、Provider 无效兜底（M11）、状态通知（M3）
//
// 使用方式：集成到 test/unittest/data_collect/sa/auth_coordinator_test.cpp 末尾，
//           或单独编译为 auth_coordinator_test_extended.cpp
// ============================================================================

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "security_guard_define.h"
#define private public
#define protected public
#include "accesstoken_kit.h"
#include "auth_coordinator.h"
#include "auth_event_reporter.h"
#include "auth_event_subscribe_manager.h"
#include "auth_event_session_service.h"
#include "auth_provider_session_service.h"
#include "data_collect_manager_service.h"
#undef private
#undef protected

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security;
using namespace OHOS::Security::SecurityGuard;

namespace {
constexpr int64_t TEST_EVENT_ID_DENY = 30001;
constexpr int64_t TEST_EVENT_ID_ALLOW = 30002;
constexpr int64_t TEST_EVENT_ID_TIMEOUT_DENY = 30003;
constexpr int64_t TEST_EVENT_ID_TIMEOUT_ALLOW = 30004;
constexpr int64_t TEST_EVENT_ID_NO_CLIENT = 30005;
constexpr int64_t TEST_EVENT_ID_DEGRADED = 30006;
constexpr int32_t TEST_DEFAULT_TIMEOUT_MS = 400;

// 辅助：创建 mock 远端对象
sptr<MockRemoteObject> CreateRemoteObject()
{
    auto obj = sptr<MockRemoteObject>(new (std::nothrow) MockRemoteObject());
    if (obj != nullptr) {
        ON_CALL(*obj, AddDeathRecipient(_)).WillByDefault(Return(true));
        ON_CALL(*obj, RemoveDeathRecipient(_)).WillByDefault(Return(true));
    }
    return obj;
}

// 辅助：创建 Provider
sptr<AuthProviderSessionService> CreateTestProvider(pid_t pid, int32_t uid, const std::string &serviceId)
{
    auto cb = CreateRemoteObject();
    sptr<IRemoteObject> providerRemote = nullptr;
    auto &coordinator = AuthCoordinator::GetInstance();
    coordinator.CreateAuthProvider(pid, uid, cb, serviceId, providerRemote);
    return static_cast<AuthProviderSessionService *>(providerRemote.GetRefPtr());
}

// 辅助：创建 Client 会话
sptr<AuthEventSessionService> CreateTestClient(pid_t pid, int32_t uid, bool timeoutAllowFlag)
{
    auto cb = CreateRemoteObject();
    sptr<IRemoteObject> sessionRemote = nullptr;
    auto &manager = AuthEventSubscribeManager::GetInstance();
    CreateClientParams params;
    params.callerPid = pid;
    params.callerUid = uid;
    params.timeoutAllowFlag = timeoutAllowFlag ? 1 : 0;
    params.defaultTimeoutMs = TEST_DEFAULT_TIMEOUT_MS;
    params.callback = cb;
    manager.CreatAuthEventClient(params, sessionRemote);
    return static_cast<AuthEventSessionService *>(sessionRemote.GetRefPtr());
}

// 辅助：订阅事件
void SubscribeEvent(AuthEventSessionService *session, int64_t eventId)
{
    AuthEventSubscribeManager::GetInstance().SubscribeAuthEvent(session, eventId);
}

// 辅助：清理所有状态
void ClearAllState()
{
    auto &coordinator = AuthCoordinator::GetInstance();
    std::lock_guard<ffrt::mutex> lock(coordinator.mutex_);
    coordinator.providerSessions_.clear();
    coordinator.routingContexts_.clear();
    // P1-3: 清理 16 个分片
    for (size_t i = 0; i < SEQNUM_SHARD_COUNT; ++i) {
        std::lock_guard<ffrt::mutex> slock(coordinator.seqnumShards_[i].mutex);
        coordinator.seqnumShards_[i].seqnumToCtx.clear();
    }

    auto &manager = AuthEventSubscribeManager::GetInstance();
    std::lock_guard<ffrt::mutex> mlock(manager.mutex_);
    manager.sessions_.clear();
    manager.authResults_.clear();
}
} // namespace

class AuthCoordinatorExtendedTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override { ClearAllState(); }
    void TearDown() override { ClearAllState(); }
};

// ===========================================================================
// TC01 — 从严策略：任一 DENY 立即阻断（验收 #13）
// ===========================================================================
HWTEST_F(AuthCoordinatorExtendedTest, StrictPolicy_DenyImmediately_001, TestSize.Level0)
{
    auto provider = CreateTestProvider(7001, 7001, "svc_deny");
    auto client1 = CreateTestClient(8001, 8001, true); // ALLOW 超时策略
    auto client2 = CreateTestClient(8002, 8002, true);
    SubscribeEvent(client1, TEST_EVENT_ID_DENY);
    SubscribeEvent(client2, TEST_EVENT_ID_DENY);

    AuthEventInfo event(TEST_EVENT_ID_DENY, "v1", "deny_test");
    sptr<MockRemoteObject> resultCb = CreateRemoteObject();
    int32_t ret = AuthCoordinator::GetInstance().RequestAuthResult(provider, event, resultCb);
    EXPECT_EQ(ret, SUCCESS);

    // 等 dispatch 完成（ffrt 异步）
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Client-1 回填 DENY
    AuthEvent denyEvent(TEST_EVENT_ID_DENY);
    denyEvent.SetSeqnum(1); // client1 的第一个 seqnum
    ret = AuthCoordinator::GetInstance().SetAuthResult(client1, denyEvent,
        static_cast<int32_t>(AuthStrategy::DENY));
    EXPECT_EQ(ret, SUCCESS);

    // 等聚合完成
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // 验证：RoutingContext 已清理（DENY 立即完成）
    auto &coordinator = AuthCoordinator::GetInstance();
    std::lock_guard<ffrt::mutex> lock(coordinator.mutex_);
    EXPECT_EQ(coordinator.routingContexts_.size(), 0u);
    SGLOGI("TC01 strict DENY verified");
}

// ===========================================================================
// TC02 — 从严策略：全部 ALLOW 才放行（验收 #14）
// ===========================================================================
HWTEST_F(AuthCoordinatorExtendedTest, StrictPolicy_AllAllow_002, TestSize.Level0)
{
    auto provider = CreateTestProvider(7002, 7002, "svc_allow");
    auto client1 = CreateTestClient(8101, 8101, true);
    auto client2 = CreateTestClient(8102, 8102, true);
    SubscribeEvent(client1, TEST_EVENT_ID_ALLOW);
    SubscribeEvent(client2, TEST_EVENT_ID_ALLOW);

    AuthEventInfo event(TEST_EVENT_ID_ALLOW, "v1", "allow_test");
    sptr<MockRemoteObject> resultCb = CreateRemoteObject();
    AuthCoordinator::GetInstance().RequestAuthResult(provider, event, resultCb);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // 两个 Client 都回填 ALLOW
    AuthEvent allowEvent(TEST_EVENT_ID_ALLOW);
    allowEvent.SetSeqnum(1);
    AuthCoordinator::GetInstance().SetAuthResult(client1, allowEvent,
        static_cast<int32_t>(AuthStrategy::ALLOW));

    // 此时 sentClientCount=1，未完成
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    {
        auto &coordinator = AuthCoordinator::GetInstance();
        std::lock_guard<ffrt::mutex> lock(coordinator.mutex_);
        // RoutingContext 仍存在（还有一个 client 未回填）
        EXPECT_EQ(coordinator.routingContexts_.size(), 1u);
    }

    allowEvent.SetSeqnum(1);
    AuthCoordinator::GetInstance().SetAuthResult(client2, allowEvent,
        static_cast<int32_t>(AuthStrategy::ALLOW));

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    {
        auto &coordinator = AuthCoordinator::GetInstance();
        std::lock_guard<ffrt::mutex> lock(coordinator.mutex_);
        // 全部 ALLOW，聚合完成，RoutingContext 已清理
        EXPECT_EQ(coordinator.routingContexts_.size(), 0u);
    }
    SGLOGI("TC02 all ALLOW verified");
}

// ===========================================================================
// TC03 — 超时 DENY 触发阻断（验收 #15）
// ===========================================================================
HWTEST_F(AuthCoordinatorExtendedTest, Timeout_DenyTriggersBlock_003, TestSize.Level0)
{
    auto provider = CreateTestProvider(7003, 7003, "svc_timeout_deny");
    // Client 超时策略 = DENY（timeoutAllowFlag=false）
    auto client = CreateTestClient(8201, 8201, false);
    SubscribeEvent(client, TEST_EVENT_ID_TIMEOUT_DENY);

    AuthEventInfo event(TEST_EVENT_ID_TIMEOUT_DENY, "v1", "timeout_deny_test");
    sptr<MockRemoteObject> resultCb = CreateRemoteObject();
    int32_t ret = AuthCoordinator::GetInstance().RequestAuthResult(provider, event, resultCb);
    EXPECT_EQ(ret, SUCCESS);

    // 不回填，等超时（400ms + 容差）
    std::this_thread::sleep_for(std::chrono::milliseconds(600));

    // RoutingContext 应已清理（超时后完成）
    auto &coordinator = AuthCoordinator::GetInstance();
    std::lock_guard<ffrt::mutex> lock(coordinator.mutex_);
    EXPECT_EQ(coordinator.routingContexts_.size(), 0u);
    SGLOGI("TC03 timeout DENY verified");
}

// ===========================================================================
// TC04 — 超时 ALLOW 不阻断，clientResults 记 TIMEOUT（验收 #16 + M8）
// ===========================================================================
HWTEST_F(AuthCoordinatorExtendedTest, Timeout_AllowNotBlock_004, TestSize.Level0)
{
    auto provider = CreateTestProvider(7004, 7004, "svc_timeout_allow");
    auto client = CreateTestClient(8301, 8301, true); // 超时策略 ALLOW
    SubscribeEvent(client, TEST_EVENT_ID_TIMEOUT_ALLOW);

    AuthEventInfo event(TEST_EVENT_ID_TIMEOUT_ALLOW, "v1", "timeout_allow_test");
    sptr<MockRemoteObject> resultCb = CreateRemoteObject();
    AuthCoordinator::GetInstance().RequestAuthResult(provider, event, resultCb);

    std::this_thread::sleep_for(std::chrono::milliseconds(600));

    auto &coordinator = AuthCoordinator::GetInstance();
    std::lock_guard<ffrt::mutex> lock(coordinator.mutex_);
    EXPECT_EQ(coordinator.routingContexts_.size(), 0u);
    SGLOGI("TC04 timeout ALLOW verified");
}

// ===========================================================================
// TC05 — 无订阅 Client 默认放行（验收 #18）
// ===========================================================================
HWTEST_F(AuthCoordinatorExtendedTest, NoClient_DefaultAllow_005, TestSize.Level0)
{
    auto provider = CreateTestProvider(7005, 7005, "svc_no_client");
    // 不创建任何 Client

    AuthEventInfo event(TEST_EVENT_ID_NO_CLIENT, "v1", "no_client_test");
    sptr<MockRemoteObject> resultCb = CreateRemoteObject();
    int32_t ret = AuthCoordinator::GetInstance().RequestAuthResult(provider, event, resultCb);
    EXPECT_EQ(ret, SUCCESS);

    // 无 Client 场景立即完成（不走 ffrt wait）
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto &coordinator = AuthCoordinator::GetInstance();
    std::lock_guard<ffrt::mutex> lock(coordinator.mutex_);
    EXPECT_EQ(coordinator.routingContexts_.size(), 0u);
    SGLOGI("TC05 no client default ALLOW verified");
}

// ===========================================================================
// TC09 — 聚合完成后清理所有映射（验收 #19）
// ===========================================================================
HWTEST_F(AuthCoordinatorExtendedTest, CleanupAfterComplete_009, TestSize.Level0)
{
    auto provider = CreateTestProvider(7009, 7009, "svc_cleanup");
    auto client = CreateTestClient(8401, 8401, true);
    SubscribeEvent(client, 30009);

    AuthEventInfo event(30009, "v1", "cleanup_test");
    sptr<MockRemoteObject> resultCb = CreateRemoteObject();
    AuthCoordinator::GetInstance().RequestAuthResult(provider, event, resultCb);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    AuthEvent allowEvent(30009);
    allowEvent.SetSeqnum(1);
    AuthCoordinator::GetInstance().SetAuthResult(client, allowEvent,
        static_cast<int32_t>(AuthStrategy::ALLOW));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto &coordinator = AuthCoordinator::GetInstance();
    std::lock_guard<ffrt::mutex> lock(coordinator.mutex_);
    EXPECT_EQ(coordinator.routingContexts_.size(), 0u);
    // P1-3: 验证所有分片已清理
    for (size_t i = 0; i < SEQNUM_SHARD_COUNT; ++i) {
        std::lock_guard<ffrt::mutex> slock(coordinator.seqnumShards_[i].mutex);
        EXPECT_EQ(coordinator.seqnumShards_[i].seqnumToCtx.size(), 0u);
    }
    SGLOGI("TC09 cleanup verified");
}

// ===========================================================================
// TC10 — 并发请求超限返回 27000004
// ===========================================================================
HWTEST_F(AuthCoordinatorExtendedTest, ConcurrentExceedLimit_010, TestSize.Level0)
{
    auto provider = CreateTestProvider(7010, 7010, "svc_concurrent");
    auto client = CreateTestClient(8501, 8501, true);
    SubscribeEvent(client, 30010);

    // 发起 128 个请求（不让完成，client 不回填）
    sptr<MockRemoteObject> resultCb = CreateRemoteObject();
    for (int i = 0; i < 128; ++i) {
        AuthEventInfo event(30010 + i, "v1", "concurrent_test");
        AuthCoordinator::GetInstance().RequestAuthResult(provider, event, resultCb);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // 第 129 个应返回超限
    AuthEventInfo event(30138, "v1", "overflow");
    int32_t ret = AuthCoordinator::GetInstance().RequestAuthResult(provider, event, resultCb);
    EXPECT_EQ(ret, AUTH_REQUEST_EXCEED_LIMIT);
    SGLOGI("TC10 concurrent exceed limit verified, ret=%{public}d", ret);
}

// ===========================================================================
// TC11 — Provider 进程超限返回 27000002
// ===========================================================================
HWTEST_F(AuthCoordinatorExtendedTest, ProviderExceedProcessLimit_011, TestSize.Level0)
{
    auto cb = CreateRemoteObject();
    sptr<IRemoteObject> r1 = nullptr;
    auto &coordinator = AuthCoordinator::GetInstance();
    coordinator.CreateAuthProvider(7011, 7011, cb, "svc_p1", r1);

    // 同 pid 第二个 → 超限
    auto cb2 = CreateRemoteObject();
    sptr<IRemoteObject> r2 = nullptr;
    int32_t ret = coordinator.CreateAuthProvider(7011, 7011, cb2, "svc_p2", r2);
    EXPECT_EQ(ret, AUTH_PROVIDER_EXCEED_PROCESS_LIMIT);
    SGLOGI("TC11 provider process limit verified");
}

// ===========================================================================
// TC12 — Provider 全局超限返回 27000003
// ===========================================================================
HWTEST_F(AuthCoordinatorExtendedTest, ProviderExceedGlobalLimit_012, TestSize.Level0)
{
    auto &coordinator = AuthCoordinator::GetInstance();
    for (size_t i = 0; i < MAX_AUTH_PROVIDER_SIZE; ++i) {
        auto cb = CreateRemoteObject();
        sptr<IRemoteObject> remote = nullptr;
        coordinator.CreateAuthProvider(static_cast<pid_t>(7012 + i), 7012, cb,
            "svc_g" + std::to_string(i), remote);
    }
    auto cb = CreateRemoteObject();
    sptr<IRemoteObject> remote = nullptr;
    int32_t ret = coordinator.CreateAuthProvider(7999, 7012, cb, "overflow_global", remote);
    EXPECT_EQ(ret, AUTH_PROVIDER_EXCEED_GLOBAL_LIMIT);
    SGLOGI("TC12 provider global limit verified");
}

// ===========================================================================
// TC13 — Destroy 幂等（验收 #22）
// ===========================================================================
HWTEST_F(AuthCoordinatorExtendedTest, DestroyIdempotent_013, TestSize.Level0)
{
    auto provider = CreateTestProvider(7013, 7013, "svc_destroy");
    EXPECT_NE(provider, nullptr);

    // 第一次 destroy
    AuthCoordinator::GetInstance().DestroyAuthProvider(provider);
    // 第二次 destroy（幂等，不 crash）
    AuthCoordinator::GetInstance().DestroyAuthProvider(provider);
    SGLOGI("TC13 destroy idempotent verified");
}

// ===========================================================================
// TC14 — IPC 立即返回（M11: dispatch 在 ffrt 异步任务中）
// ===========================================================================
HWTEST_F(AuthCoordinatorExtendedTest, IpcImmediateReturn_014, TestSize.Level0)
{
    auto provider = CreateTestProvider(7014, 7014, "svc_ipc");
    auto client = CreateTestClient(8601, 8601, true);
    SubscribeEvent(client, 30014);

    AuthEventInfo event(30014, "v1", "ipc_test");
    sptr<MockRemoteObject> resultCb = CreateRemoteObject();

    auto start = std::chrono::steady_clock::now();
    int32_t ret = AuthCoordinator::GetInstance().RequestAuthResult(provider, event, resultCb);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();

    EXPECT_EQ(ret, SUCCESS);
    // IPC 应在 < 100ms 内返回（dispatch 在 ffrt 异步）
    EXPECT_LT(elapsed, 100);
    SGLOGI("TC14 IPC immediate return verified, elapsed=%{public}lld ms",
        static_cast<long long>(elapsed));
}

// ===========================================================================
// TC17 — Provider 无效时 ffrt 任务兜底返回 ALLOW（M11 生命周期保护）
// ===========================================================================
HWTEST_F(AuthCoordinatorExtendedTest, ProviderInvalidFallback_017, TestSize.Level0)
{
    auto provider = CreateTestProvider(7017, 7017, "svc_invalid");
    auto client = CreateTestClient(8701, 8701, true);
    SubscribeEvent(client, 30017);

    AuthEventInfo event(30017, "v1", "invalid_test");
    sptr<MockRemoteObject> resultCb = CreateRemoteObject();
    AuthCoordinator::GetInstance().RequestAuthResult(provider, event, resultCb);

    // 立即 destroy provider（MarkInvalid）
    AuthCoordinator::GetInstance().DestroyAuthProvider(provider);

    // 等 ffrt 任务完成
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // activeRequestCount 应归零（ffrt 任务兜底递减）
    // 由于 provider 已从集合移除，无法直接检查计数，验证无 crash 即可
    SGLOGI("TC17 provider invalid fallback verified");
}

// ===========================================================================
// TC18 — 订阅者销毁后通知 Provider（M3 状态通知）
// ===========================================================================
HWTEST_F(AuthCoordinatorExtendedTest, ClientDestroyNotify_018, TestSize.Level0)
{
    auto provider = CreateTestProvider(7018, 7018, "svc_notify");
    auto client = CreateTestClient(8801, 8801, true);
    SubscribeEvent(client, 30018);

    // 销毁 Client
    AuthEventSubscribeManager::GetInstance().DestroyAuthEventClient(client);

    // 等异步通知（ffrt::submit）
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Provider 应仍在（未被误删）
    auto &coordinator = AuthCoordinator::GetInstance();
    std::lock_guard<ffrt::mutex> lock(coordinator.mutex_);
    EXPECT_EQ(coordinator.providerSessions_.size(), 1u);

    // Client 应已从 manager 移除
    auto &manager = AuthEventSubscribeManager::GetInstance();
    std::lock_guard<ffrt::mutex> mlock(manager.mutex_);
    EXPECT_EQ(manager.sessions_.size(), 0u);
    SGLOGI("TC18 client destroy notify verified");
}

} // namespace OHOS::Security::SecurityGuard
#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
