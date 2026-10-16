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
#define private public
#define protected public
#include "accesstoken_kit.h"
#include "auth_coordinator.h"
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
class AuthCoordinatorTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        auto &coordinator = AuthCoordinator::GetInstance();
        std::lock_guard<ffrt::mutex> lock(coordinator.mutex_);
        coordinator.providerSessions_.clear();
        coordinator.routingContexts_.clear();
        coordinator.seqnumToEventId_.clear();

        auto &manager = AuthEventSubscribeManager::GetInstance();
        std::lock_guard<ffrt::mutex> mlock(manager.mutex_);
        manager.sessions_.clear();
        manager.authResults_.clear();
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
}

HWTEST_F(AuthCoordinatorTest, CreateProvider001, TestSize.Level0)
{
    auto cb = CreateRemoteObject();
    sptr<IRemoteObject> providerRemote = nullptr;
    auto &coordinator = AuthCoordinator::GetInstance();
    int32_t ret = coordinator.CreateAuthProvider(1000, 1000, cb, "test_service", providerRemote);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_NE(providerRemote, nullptr);
}

HWTEST_F(AuthCoordinatorTest, CreateProviderDuplicateCallback001, TestSize.Level0)
{
    auto cb = CreateRemoteObject();
    sptr<IRemoteObject> providerRemote = nullptr;
    auto &coordinator = AuthCoordinator::GetInstance();
    coordinator.CreateAuthProvider(1000, 1000, cb, "test_service", providerRemote);
    sptr<IRemoteObject> providerRemote2 = nullptr;
    int32_t ret = coordinator.CreateAuthProvider(1000, 1000, cb, "test_service2", providerRemote2);
    EXPECT_EQ(ret, BAD_PARAM);
}

HWTEST_F(AuthCoordinatorTest, CreateProviderExceedProcessLimit001, TestSize.Level0)
{
    auto cb1 = CreateRemoteObject();
    auto cb2 = CreateRemoteObject();
    sptr<IRemoteObject> r1 = nullptr;
    sptr<IRemoteObject> r2 = nullptr;
    auto &coordinator = AuthCoordinator::GetInstance();
    coordinator.CreateAuthProvider(2000, 2000, cb1, "svc1", r1);
    int32_t ret = coordinator.CreateAuthProvider(2000, 2000, cb2, "svc2", r2);
    EXPECT_EQ(ret, AUTH_PROVIDER_EXCEED_PROCESS_LIMIT);
}

HWTEST_F(AuthCoordinatorTest, DestroyProvider001, TestSize.Level0)
{
    auto cb = CreateRemoteObject();
    sptr<IRemoteObject> providerRemote = nullptr;
    auto &coordinator = AuthCoordinator::GetInstance();
    coordinator.CreateAuthProvider(3000, 3000, cb, "svc", providerRemote);
    auto *provider = static_cast<AuthProviderSessionService *>(providerRemote.GetRefPtr());
    coordinator.DestroyAuthProvider(provider);
    EXPECT_FALSE(provider->IsValid());
}

HWTEST_F(AuthCoordinatorTest, DestroyProviderInvalid001, TestSize.Level0)
{
    auto &coordinator = AuthCoordinator::GetInstance();
    coordinator.DestroyAuthProvider(nullptr);
}

HWTEST_F(AuthCoordinatorTest, RequestAuthResultNoClient001, TestSize.Level0)
{
    auto cb = CreateRemoteObject();
    sptr<IRemoteObject> providerRemote = nullptr;
    auto &coordinator = AuthCoordinator::GetInstance();
    coordinator.CreateAuthProvider(4000, 4000, cb, "svc", providerRemote);
    auto *provider = static_cast<AuthProviderSessionService *>(providerRemote.GetRefPtr());

    AuthEventInfo event(1001, "v1", "content");
    int32_t ret = coordinator.RequestAuthResult(provider, event, nullptr);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(AuthCoordinatorTest, SetAuthResultNoRoutingContext001, TestSize.Level0)
{
    auto cb = CreateRemoteObject();
    sptr<IRemoteObject> sessionRemote = nullptr;
    auto &manager = AuthEventSubscribeManager::GetInstance();
    CreateClientParams params;
    params.callerPid = 5000;
    params.callerUid = 5000;
    params.timeoutAllowFlag = 1;
    params.defaultTimeoutMs = TEST_DEFAULT_TIMEOUT_MS;
    params.callback = cb;
    manager.CreatAuthEventClient(params, sessionRemote);
    auto *session = static_cast<AuthEventSessionService *>(sessionRemote.GetRefPtr());

    AuthEvent event(2001);
    int32_t ret = AuthCoordinator::GetInstance().SetAuthResult(session, event, AuthStrategy::ALLOW);
    EXPECT_EQ(ret, NOT_FOUND);
}

HWTEST_F(AuthCoordinatorTest, ProviderQuotaGlobalLimit001, TestSize.Level0)
{
    auto &coordinator = AuthCoordinator::GetInstance();
    for (size_t i = 0; i < MAX_AUTH_PROVIDER_SIZE; ++i) {
        auto cb = CreateRemoteObject();
        sptr<IRemoteObject> remote = nullptr;
        coordinator.CreateAuthProvider(static_cast<pid_t>(6000 + i), 6000, cb,
            "svc" + std::to_string(i), remote);
    }
    auto cb = CreateRemoteObject();
    sptr<IRemoteObject> remote = nullptr;
    int32_t ret = coordinator.CreateAuthProvider(6999, 6000, cb, "overflow", remote);
    EXPECT_EQ(ret, AUTH_PROVIDER_EXCEED_GLOBAL_LIMIT);
}
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
