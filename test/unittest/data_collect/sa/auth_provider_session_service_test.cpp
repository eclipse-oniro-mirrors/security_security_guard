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
class AuthProviderSessionServiceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        auto &coordinator = AuthCoordinator::GetInstance();
        std::lock_guard<ffrt::mutex> lock(coordinator.mutex_);
        coordinator.providerSessions_.clear();
        coordinator.routingContexts_.clear();
        for (auto &shard : coordinator.seqnumShards_) {
            shard.seqnumToCtx.clear();
        }
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

HWTEST_F(AuthProviderSessionServiceTest, Construct001, TestSize.Level0)
{
    auto cb = CreateRemoteObject();
    AuthProviderSessionService provider(7000, 7000, "test_svc", cb);
    EXPECT_EQ(provider.GetPid(), 7000);
    EXPECT_EQ(provider.GetUid(), 7000);
    EXPECT_EQ(provider.GetServiceId(), "test_svc");
    EXPECT_TRUE(provider.IsValid());
}

HWTEST_F(AuthProviderSessionServiceTest, MarkInvalid001, TestSize.Level0)
{
    auto cb = CreateRemoteObject();
    AuthProviderSessionService provider(7001, 7001, "svc", cb);
    provider.MarkInvalid();
    EXPECT_FALSE(provider.IsValid());
}

HWTEST_F(AuthProviderSessionServiceTest, RequestAuthResultInvalidProvider001, TestSize.Level0)
{
    auto cb = CreateRemoteObject();
    AuthProviderSessionService provider(7002, 7002, "svc", cb);
    provider.MarkInvalid();
    AuthEventInfo event(3001, "v1", "content");
    ErrCode ret = provider.RequestAuthResult(event, nullptr);
    EXPECT_EQ(ret, BAD_PARAM);
}

HWTEST_F(AuthProviderSessionServiceTest, DestroyAfterInvalid001, TestSize.Level0)
{
    auto &coordinator = AuthCoordinator::GetInstance();
    auto cb = CreateRemoteObject();
    sptr<IRemoteObject> providerRemote = nullptr;
    coordinator.CreateAuthProvider(7003, 7003, cb, "svc", providerRemote);
    auto *provider = static_cast<AuthProviderSessionService *>(providerRemote.GetRefPtr());
    ASSERT_NE(provider, nullptr);

    coordinator.DestroyAuthProvider(provider);
    EXPECT_FALSE(provider->IsValid());

    coordinator.DestroyAuthProvider(provider);
}

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
