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

#include "message_parcel.h"
#include "security_guard_define.h"
#include "auth_event.h"
#include "auth_event_callback_service.h"
#include "auth_event_callback_stub.h"
#define private public
#include "auth_event_subscribe_client.h"
#undef private

#ifdef SECURITY_GUARD_AUTH_EVENT_ENABLE
using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;

namespace {
class MockRemoteObjectForSdkTest final : public OHOS::IRemoteObject {
public:
    MockRemoteObjectForSdkTest() : OHOS::IRemoteObject(u"") {}
    ~MockRemoteObjectForSdkTest() override = default;
    MOCK_METHOD0(GetObjectRefCount, int32_t());
    MOCK_METHOD4(SendRequest, int(uint32_t code, OHOS::MessageParcel &data, OHOS::MessageParcel &reply,
        OHOS::MessageOption &option));
    MOCK_METHOD1(AddDeathRecipient, bool(const OHOS::sptr<OHOS::IRemoteObject::DeathRecipient> &recipient));
    MOCK_METHOD1(RemoveDeathRecipient, bool(const OHOS::sptr<OHOS::IRemoteObject::DeathRecipient> &recipient));
    MOCK_METHOD2(Dump, int(int fd, const std::vector<std::u16string> &args));
};

class AuthEventSdkTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

// 注入服务端下发形态的会话对象远端引用（无 SA 3524 环境，proxy 走 mock SendRequest）
OHOS::sptr<MockRemoteObjectForSdkTest> CreateFakeSessionRemote()
{
    auto remote = OHOS::sptr<MockRemoteObjectForSdkTest>(new (std::nothrow) MockRemoteObjectForSdkTest());
    if (remote != nullptr) {
        ON_CALL(*remote, AddDeathRecipient(_)).WillByDefault(Return(true));
        ON_CALL(*remote, RemoveDeathRecipient(_)).WillByDefault(Return(true));
        ON_CALL(*remote, SendRequest(_, _, _, _)).WillByDefault(Return(-1));
    }
    return remote;
}
}

HWTEST_F(AuthEventSdkTest, CallbackServiceOnAuthEvent001, TestSize.Level0)
{
    auto service = new (std::nothrow) AuthEventCallbackService();
    ASSERT_NE(nullptr, service);
    int64_t receivedId = 0;
    service->RegistCallBack([&receivedId](const AuthEvent &event) { receivedId = event.GetEventId(); });
    AuthEvent event(1001, "content", "metadata");
    EXPECT_EQ(service->OnAuthEvent(event), SUCCESS);
    EXPECT_EQ(1001L, receivedId);
    // 清空回调后不再触发
    service->ClearCallBack();
    EXPECT_EQ(service->OnAuthEvent(event), FAILED);
    EXPECT_EQ(1001L, receivedId);
    delete service;
}

HWTEST_F(AuthEventSdkTest, CallbackStubOnRemoteRequest001, TestSize.Level0)
{
    auto service = new (std::nothrow) AuthEventCallbackService();
    ASSERT_NE(nullptr, service);
    int64_t receivedId = 0;
    service->RegistCallBack([&receivedId](const AuthEvent &event) { receivedId = event.GetEventId(); });
    AuthEvent event(2002, "content", "metadata");
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    data.WriteInterfaceToken(AuthEventCallbackStub::GetDescriptor());
    ASSERT_TRUE(data.WriteParcelable(&event));
    EXPECT_EQ(service->OnRemoteRequest(IAuthEventCallback::CMD_ON_AUTH_EVENT, data, reply, option), SUCCESS);
    EXPECT_EQ(2002L, receivedId);
    delete service;
}

HWTEST_F(AuthEventSdkTest, CallbackStubOnRemoteRequest002, TestSize.Level0)
{
    auto service = new (std::nothrow) AuthEventCallbackService();
    ASSERT_NE(nullptr, service);
    AuthEvent event(2003);
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    // 接口 token 不匹配
    data.WriteInterfaceToken(u"OHOS.Security.FakeDescriptor");
    ASSERT_TRUE(data.WriteParcelable(&event));
    EXPECT_EQ(service->OnRemoteRequest(IAuthEventCallback::CMD_ON_AUTH_EVENT, data, reply, option),
        NO_PERMISSION);
    // 空 parcel 读不到事件
    OHOS::MessageParcel emptyData;
    OHOS::MessageParcel emptyReply;
    emptyData.WriteInterfaceToken(AuthEventCallbackStub::GetDescriptor());
    EXPECT_EQ(service->OnRemoteRequest(IAuthEventCallback::CMD_ON_AUTH_EVENT, emptyData, emptyReply, option),
        BAD_PARAM);
    // 未知接口码
    OHOS::MessageParcel badCodeData;
    OHOS::MessageParcel badCodeReply;
    badCodeData.WriteInterfaceToken(AuthEventCallbackStub::GetDescriptor());
    ASSERT_TRUE(badCodeData.WriteParcelable(&event));
    EXPECT_EQ(service->OnRemoteRequest(0xFFFFFFFF, badCodeData, badCodeReply, option), NO_PERMISSION);
    delete service;
}

HWTEST_F(AuthEventSdkTest, ClientCreatClient001, TestSize.Level0)
{
    std::shared_ptr<AuthEventSubscribeClient> client;
    // 回调为空
    EXPECT_EQ(AuthEventSubscribeClient::CreatClient(nullptr, client), NULL_OBJECT);
    EXPECT_EQ(client, nullptr);
    // 正常回调：单测进程无 SA 3524 环境，创建失败但不得崩溃、client 不落值
    auto func = [](const AuthEvent &event) {};
    int32_t ret = AuthEventSubscribeClient::CreatClient(func, client);
    EXPECT_NE(ret, SUCCESS);
    EXPECT_EQ(client, nullptr);
}

HWTEST_F(AuthEventSdkTest, ClientMethodsBeforeCreate001, TestSize.Level0)
{
    // 会话对象引用为空：各方法返回 NULL_OBJECT
    auto client = std::make_shared<AuthEventSubscribeClient>();
    AuthEvent event(3001, "content", "metadata");
    EXPECT_EQ(client->Subscribe(11), NULL_OBJECT);
    EXPECT_EQ(client->Unsubscribe(11), NULL_OBJECT);
    EXPECT_EQ(client->SetAuthResult(event, true), NULL_OBJECT);
    // 幂等 DeleteClient 不崩溃
    client->DeleteClient();
    client->DeleteClient();
    // 已销毁（deleted_ 置位）后各方法返回 BAD_PARAM
    EXPECT_EQ(client->Subscribe(11), BAD_PARAM);
    EXPECT_EQ(client->Unsubscribe(11), BAD_PARAM);
    EXPECT_EQ(client->SetAuthResult(event, true), BAD_PARAM);
}

HWTEST_F(AuthEventSdkTest, ClientMethodsWithFakeSession001, TestSize.Level0)
{
    // 注入服务端下发形态的会话对象远端引用：各方法经 session 代理走 SendRequest
    // 失败路径（mock 返回 -1），不崩溃且返回非 SUCCESS
    auto client = std::make_shared<AuthEventSubscribeClient>();
    client->sessionRemote_ = CreateFakeSessionRemote();
    AuthEvent event(3002, "content", "metadata");
    EXPECT_NE(client->Subscribe(12), SUCCESS);
    EXPECT_NE(client->Unsubscribe(12), SUCCESS);
    EXPECT_NE(client->SetAuthResult(event, true), SUCCESS);
    client->DeleteClient();
}

HWTEST_F(AuthEventSdkTest, ClientDestructor001, TestSize.Level0)
{
    // 析构兜底：注入假会话对象引用后释放最后一个 shared_ptr，
    // Destroy 经 mock SendRequest 失败路径执行，不崩溃
    {
        auto client = std::make_shared<AuthEventSubscribeClient>();
        client->sessionRemote_ = CreateFakeSessionRemote();
    }
    SUCCEED();
}

HWTEST_F(AuthEventSdkTest, ClientSetDeathRecipient001, TestSize.Level0)
{
    auto client = std::make_shared<AuthEventSubscribeClient>();
    client->sessionRemote_ = CreateFakeSessionRemote();
    OHOS::sptr<MockRemoteObjectForSdkTest> remote(new (std::nothrow) MockRemoteObjectForSdkTest());
    ASSERT_NE(remote, nullptr);
    EXPECT_CALL(*remote, AddDeathRecipient(_)).WillOnce(Return(false));
    EXPECT_EQ(AuthEventSubscribeClient::SetDeathRecipient(client, remote), SUCCESS);
    EXPECT_NE(client->deathRecipient_, nullptr);
    client->DeleteClient();
}

#endif // SECURITY_GUARD_AUTH_EVENT_ENABLE
