/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "security_collector_test.h"

#include <thread>

#include "directory_ex.h"
#include "file_ex.h"
#include "gmock/gmock.h"
#include "system_ability_definition.h"

#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#define private public
#define protected public
#include "data_collection.h"
#include "collector_cfg_marshalling.h"
#include "accesstoken_kit.h"
#include "security_collector_manager_service.h"
#include "security_collector_run_manager.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityCollector;

namespace OHOS {
    std::shared_ptr<Security::AccessToken::MockAccessTokenKitInterface>
        Security::AccessToken::AccessTokenKit::instance_ = nullptr;
    std::shared_ptr<Security::AccessToken::MockTokenIdKitInterface>
        Security::AccessToken::TokenIdKit::instance_ = nullptr;
    std::mutex Security::AccessToken::AccessTokenKit::mutex_ {};
    std::mutex Security::AccessToken::TokenIdKit::mutex_ {};
    constexpr char PERMISSION[] = "ohos.permission.securityguard.REQUEST_SECURITY_EVENT_INFO";
}

namespace OHOS::Security::SecurityCollectorTest {
SecurityCollectorManagerService g_service(SECURITY_COLLECTOR_MANAGER_SA_ID, true);
void SecurityCollectorTest::SetUpTestCase()
{
}

void SecurityCollectorTest::TearDownTestCase()
{
    AccessToken::AccessTokenKit::DelInterface();
    AccessToken::TokenIdKit::DelInterface();
}

void SecurityCollectorTest::SetUp()
{
    testing::Mock::VerifyAndClearExpectations(AccessToken::AccessTokenKit::GetInterface().get());
}

void SecurityCollectorTest::TearDown()
{
}

class MockRemoteObject final : public IRemoteObject {
public:
    MockRemoteObject() : IRemoteObject(u"")
    {
    }
    MOCK_METHOD0(GetObjectRefCount, int32_t());
    MOCK_METHOD4(SendRequest, int(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option));
    MOCK_METHOD1(AddDeathRecipient, bool(const sptr<DeathRecipient> &recipient));
    MOCK_METHOD1(RemoveDeathRecipient, bool(const sptr<DeathRecipient> &recipient));
    MOCK_METHOD2(Dump, int(int fd, const std::vector<std::u16string> &args));
};

HWTEST_F(SecurityCollectorTest, GetAppName01, TestSize.Level1)
{
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType).WillOnce(
        Return(AccessToken::ATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetHapTokenInfo).WillOnce(
        Return(SecurityCollector::ErrorCode::FAILED));
    EXPECT_EQ(SecurityCollectorManagerService::GetAppName(), "");
}

HWTEST_F(SecurityCollectorTest, GetAppName02, TestSize.Level1)
{
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType).WillOnce(
        Return(AccessToken::ATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetHapTokenInfo).WillRepeatedly(
        [] (AccessToken::AccessTokenID tokenID, AccessToken::HapTokenInfo& hapTokenInfoRes) {
            hapTokenInfoRes.bundleName = "bundleName";
            return SecurityCollector::ErrorCode::SUCCESS;
        });
    EXPECT_EQ(SecurityCollectorManagerService::GetAppName(), "bundleName");
}

HWTEST_F(SecurityCollectorTest, GetAppName03, TestSize.Level1)
{
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType).WillOnce(
        Return(AccessToken::ATokenTypeEnum::TOKEN_NATIVE));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetNativeTokenInfo).WillOnce(
        Return(SecurityCollector::ErrorCode::FAILED));
    EXPECT_EQ(SecurityCollectorManagerService::GetAppName(), "");
}

HWTEST_F(SecurityCollectorTest, GetAppName04, TestSize.Level1)
{
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType).WillOnce(
        Return(AccessToken::ATokenTypeEnum::TOKEN_NATIVE));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetNativeTokenInfo).WillOnce(
        [] (AccessToken::AccessTokenID tokenID, AccessToken::NativeTokenInfo& nativeTokenInfoRes) {
            nativeTokenInfoRes.processName = "processName";
            return SecurityCollector::ErrorCode::SUCCESS;
        });
    EXPECT_EQ(SecurityCollectorManagerService::GetAppName(), "processName");
}

HWTEST_F(SecurityCollectorTest, GetAppName05, TestSize.Level1)
{
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType).WillRepeatedly(
        Return(AccessToken::ATokenTypeEnum::TOKEN_INVALID));
    EXPECT_EQ(SecurityCollectorManagerService::GetAppName(), "");
}

HWTEST_F(SecurityCollectorTest, HasPermission01, TestSize.Level1)
{
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_DENIED));
    EXPECT_EQ(SecurityCollectorManagerService::HasPermission(PERMISSION), SecurityCollector::ErrorCode::NO_PERMISSION);
}

HWTEST_F(SecurityCollectorTest, HasPermission02, TestSize.Level1)
{
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_EQ(SecurityCollectorManagerService::HasPermission(PERMISSION), SecurityCollector::ErrorCode::SUCCESS);
}

HWTEST_F(SecurityCollectorTest, HasPermission03, TestSize.Level1)
{
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_EQ(SecurityCollectorManagerService::HasPermission(PERMISSION), SecurityCollector::ErrorCode::SUCCESS);
}

HWTEST_F(SecurityCollectorTest, Subscribe01, TestSize.Level1)
{
    SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_DENIED));
    EXPECT_EQ(g_service.Subscribe(subscribeInfo, obj), SecurityCollector::ErrorCode::NO_PERMISSION);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

HWTEST_F(SecurityCollectorTest, Unsubscribe01, TestSize.Level1)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_DENIED));
    EXPECT_EQ(g_service.Unsubscribe(obj), SecurityCollector::ErrorCode::NO_PERMISSION);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

HWTEST_F(SecurityCollectorTest, CollectorStart01, TestSize.Level1)
{
    SecurityCollectorSubscribeInfo info{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_DENIED));
    EXPECT_EQ(g_service.CollectorStart(info, obj), SecurityCollector::ErrorCode::NO_PERMISSION);
}

HWTEST_F(SecurityCollectorTest, CollectorStart02, TestSize.Level1)
{
    SecurityCollectorSubscribeInfo info{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(DataCollection::GetInstance(), GetCollectorType).WillOnce(Return(SecurityCollector::ErrorCode::FAILED));
    EXPECT_EQ(g_service.CollectorStart(info, obj), SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, CollectorStart03, TestSize.Level1)
{
    SecurityCollectorSubscribeInfo info{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(DataCollection::GetInstance(), GetCollectorType).WillOnce([] (int64_t eventId, int32_t& collectorType) {
        collectorType = 0;
        return SecurityCollector::ErrorCode::SUCCESS;
    });
    EXPECT_EQ(g_service.CollectorStart(info, obj), SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, CollectorStart04, TestSize.Level1)
{
    SecurityCollectorSubscribeInfo info{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(DataCollection::GetInstance(), GetCollectorType).WillOnce([] (int64_t eventId, int32_t& collectorType) {
        collectorType = 1;
        return SecurityCollector::ErrorCode::SUCCESS;
    });
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType).WillOnce(
        Return(AccessToken::ATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetHapTokenInfo).WillOnce(
        Return(SecurityCollector::ErrorCode::FAILED));
    EXPECT_EQ(g_service.CollectorStart(info, obj), SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, CollectorStart05, TestSize.Level1)
{
    SecurityCollectorSubscribeInfo info{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(DataCollection::GetInstance(), GetCollectorType).WillOnce([] (int64_t eventId, int32_t& collectorType) {
        collectorType = 1;
        return SecurityCollector::ErrorCode::SUCCESS;
    });
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType).WillOnce(
        Return(AccessToken::ATokenTypeEnum::TOKEN_NATIVE));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetNativeTokenInfo).WillOnce(
        [] (AccessToken::AccessTokenID tokenID, AccessToken::NativeTokenInfo& nativeTokenInfoRes) {
            nativeTokenInfoRes.processName = "processName";
            return SecurityCollector::ErrorCode::SUCCESS;
        });
    EXPECT_CALL(SecurityCollectorRunManager::GetInstance(), StartCollector).WillOnce(Return(false));
    EXPECT_EQ(g_service.CollectorStart(info, obj), SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, CollectorStart06, TestSize.Level1)
{
    SecurityCollectorSubscribeInfo info{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(DataCollection::GetInstance(), GetCollectorType).WillOnce([] (int64_t eventId, int32_t& collectorType) {
        collectorType = 1;
        return SecurityCollector::ErrorCode::SUCCESS;
    });
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType).WillOnce(
        Return(AccessToken::ATokenTypeEnum::TOKEN_NATIVE));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetNativeTokenInfo).WillOnce(
        [] (AccessToken::AccessTokenID tokenID, AccessToken::NativeTokenInfo& nativeTokenInfoRes) {
            nativeTokenInfoRes.processName = "processName";
            return SecurityCollector::ErrorCode::SUCCESS;
        });
    EXPECT_CALL(SecurityCollectorRunManager::GetInstance(), StartCollector).WillOnce(Return(true));
    EXPECT_EQ(g_service.CollectorStart(info, obj), SecurityCollector::ErrorCode::SUCCESS);
}

HWTEST_F(SecurityCollectorTest, CollectorStop01, TestSize.Level1)
{
    SecurityCollectorSubscribeInfo info{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_DENIED));
    EXPECT_EQ(g_service.CollectorStop(info, obj), SecurityCollector::ErrorCode::NO_PERMISSION);
}

HWTEST_F(SecurityCollectorTest, CollectorStop02, TestSize.Level1)
{
    SecurityCollectorSubscribeInfo info{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType).WillOnce(
        Return(AccessToken::ATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetHapTokenInfo).WillOnce(
        Return(SecurityCollector::ErrorCode::FAILED));
    EXPECT_EQ(g_service.CollectorStop(info, obj), SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, CollectorStop03, TestSize.Level1)
{
    SecurityCollectorSubscribeInfo info{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType).WillOnce(
        Return(AccessToken::ATokenTypeEnum::TOKEN_NATIVE));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetNativeTokenInfo).WillOnce(
        [] (AccessToken::AccessTokenID tokenID, AccessToken::NativeTokenInfo& nativeTokenInfoRes) {
            nativeTokenInfoRes.processName = "processName";
            return SecurityCollector::ErrorCode::SUCCESS;
        });
    EXPECT_CALL(SecurityCollectorRunManager::GetInstance(), StopCollector).WillOnce(Return(false));
    EXPECT_EQ(g_service.CollectorStop(info, obj), SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, CollectorStop04, TestSize.Level1)
{
    SecurityCollectorSubscribeInfo info{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType).WillOnce(
        Return(AccessToken::ATokenTypeEnum::TOKEN_NATIVE));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetNativeTokenInfo).WillOnce(
        [] (AccessToken::AccessTokenID tokenID, AccessToken::NativeTokenInfo& nativeTokenInfoRes) {
            nativeTokenInfoRes.processName = "processName";
            return SecurityCollector::ErrorCode::SUCCESS;
        });
    EXPECT_CALL(SecurityCollectorRunManager::GetInstance(), StopCollector).WillOnce(Return(true));
    EXPECT_EQ(g_service.CollectorStop(info, obj), SecurityCollector::ErrorCode::SUCCESS);
}

HWTEST_F(SecurityCollectorTest, ExecuteOnNotifyByTask01, TestSize.Level1)
{
    Event event{};
    sptr<MockRemoteObject> obj = nullptr;
    g_service.ExecuteOnNotifyByTask(obj, event);
    EXPECT_TRUE(obj == nullptr);
}

HWTEST_F(SecurityCollectorTest, ExecuteOnNotifyByTask02, TestSize.Level1)
{
    Event event{};
    event.eventId = SecurityCollector::FILE_EVENTID;
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    EXPECT_CALL(*obj, SendRequest)
        .WillOnce([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            g_service.OnRemoteRequest(code, data, reply, option);
            return SecurityCollector::ErrorCode::SUCCESS;
        });
    g_service.ExecuteOnNotifyByTask(obj, event);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

HWTEST_F(SecurityCollectorTest, ExecuteOnNotifyByTask03, TestSize.Level1)
{
    Event event{};
    event.eventId = SecurityCollector::PROCESS_EVENTID;
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    EXPECT_CALL(*obj, SendRequest)
        .WillOnce([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            g_service.OnRemoteRequest(code, data, reply, option);
            return SecurityCollector::ErrorCode::SUCCESS;
        });
    g_service.ExecuteOnNotifyByTask(obj, event);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

HWTEST_F(SecurityCollectorTest, ExecuteOnNotifyByTask04, TestSize.Level1)
{
    Event event{};
    event.eventId = SecurityCollector::NETWORK_EVENTID;
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    EXPECT_CALL(*obj, SendRequest)
        .WillOnce([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            g_service.OnRemoteRequest(code, data, reply, option);
            return SecurityCollector::ErrorCode::SUCCESS;
        });
    g_service.ExecuteOnNotifyByTask(obj, event);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

HWTEST_F(SecurityCollectorTest, ExecuteOnNotifyByTask05, TestSize.Level1)
{
    Event event{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    EXPECT_CALL(*obj, SendRequest)
        .WillOnce([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            g_service.OnRemoteRequest(code, data, reply, option);
            return SecurityCollector::ErrorCode::SUCCESS;
        });
    g_service.ExecuteOnNotifyByTask(obj, event);
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

HWTEST_F(SecurityCollectorTest, QuerySecurityEvent01, TestSize.Level1)
{
    std::vector<SecurityEventRuler> rulers{};
    std::vector<SecurityEvent> events{};
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_DENIED));
    EXPECT_EQ(g_service.QuerySecurityEvent(rulers, events), SecurityCollector::ErrorCode::NO_PERMISSION);
}

HWTEST_F(SecurityCollectorTest, QuerySecurityEvent02, TestSize.Level1)
{
    std::vector<SecurityEventRuler> rulers{};
    std::vector<SecurityEvent> events{};
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(DataCollection::GetInstance(), QuerySecurityEvent).WillOnce(
        Return(OHOS::Security::SecurityGuard::FAILED));
    EXPECT_EQ(g_service.QuerySecurityEvent(rulers, events), SecurityCollector::ErrorCode::READ_ERR);
}

HWTEST_F(SecurityCollectorTest, QuerySecurityEvent03, TestSize.Level1)
{
    std::vector<SecurityEventRuler> rulers{};
    std::vector<SecurityEvent> events{};
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(DataCollection::GetInstance(), QuerySecurityEvent).WillRepeatedly(Return(
        OHOS::Security::SecurityGuard::SUCCESS));
    EXPECT_EQ(g_service.QuerySecurityEvent(rulers, events), SecurityCollector::ErrorCode::SUCCESS);
}

HWTEST_F(SecurityCollectorTest, TestOnRemoteRequestWithInvalidInt, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    data.WriteInt32(SecurityCollectorManagerService::CMD_COLLECTOR_SUBCRIBE);
    int32_t result =
        g_service.OnRemoteRequest(SecurityCollectorManagerService::CMD_COLLECTOR_SUBCRIBE, data, reply, option);
    EXPECT_EQ(result, SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, TestOnRemoteRequestWithInvalidCmd, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    data.WriteInt32(100);
    int32_t result = g_service.OnRemoteRequest(100, data, reply, option);
    EXPECT_EQ(result, 305);
}

HWTEST_F(SecurityCollectorTest, TestOnRemoteRequestWithInvalidToken, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(u"InvalidToken");
    int32_t result =
        g_service.OnRemoteRequest(SecurityCollectorManagerService::CMD_COLLECTOR_SUBCRIBE, data, reply, option);
    EXPECT_EQ(result, 305);
}

HWTEST_F(SecurityCollectorTest, TestOnRemoteRequestWithCmd00, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> callback = nullptr;

    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    int32_t result =
        g_service.OnRemoteRequest(SecurityCollectorManagerService::CMD_COLLECTOR_SUBCRIBE, data, reply, option);
    EXPECT_EQ(result, SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, TestOnRemoteRequestWithCmd01, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> callback = nullptr;

    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    data.WriteParcelable(&subscribeInfo);
    data.WriteRemoteObject(callback);
    int32_t result =
        g_service.OnRemoteRequest(SecurityCollectorManagerService::CMD_COLLECTOR_SUBCRIBE, data, reply, option);
    EXPECT_EQ(result, SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, TestOnRemoteRequestWithCmd02, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> callback(new (std::nothrow) MockRemoteObject());

    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    data.WriteParcelable(&subscribeInfo);
    data.WriteRemoteObject(callback);
    int32_t result =
        g_service.OnRemoteRequest(SecurityCollectorManagerService::CMD_COLLECTOR_SUBCRIBE, data, reply, option);
    EXPECT_EQ(result, SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, TestOnRemoteRequestWithCmd03, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    int32_t result =
        g_service.OnRemoteRequest(SecurityCollectorManagerService::CMD_COLLECTOR_UNSUBCRIBE, data, reply, option);
    EXPECT_EQ(result, SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, TestOnRemoteRequestWithCmd04, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    sptr<MockRemoteObject> callback = nullptr;

    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    data.WriteRemoteObject(callback);
    int32_t result =
        g_service.OnRemoteRequest(SecurityCollectorManagerService::CMD_COLLECTOR_UNSUBCRIBE, data, reply, option);
    EXPECT_EQ(result, SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, TestOnRemoteRequestWithCmd05, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    sptr<MockRemoteObject> callback(new (std::nothrow) MockRemoteObject());

    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    data.WriteRemoteObject(callback);
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    int32_t result =
        g_service.OnRemoteRequest(SecurityCollectorManagerService::CMD_COLLECTOR_UNSUBCRIBE, data, reply, option);
    EXPECT_EQ(result, SecurityCollector::ErrorCode::FAILED);
}

HWTEST_F(SecurityCollectorTest, TestOnRemoteRequestWithCmd06, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    sptr<MockRemoteObject> callback(new (std::nothrow) MockRemoteObject());

    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    int32_t result =
        g_service.OnRemoteRequest(SecurityCollectorManagerService::CMD_COLLECTOR_START, data, reply, option);
    EXPECT_EQ(result, SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, TestOnRemoteRequestWithCmd07, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> callback = nullptr;

    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    data.WriteParcelable(&subscribeInfo);
    data.WriteRemoteObject(callback);
    int32_t result =
        g_service.OnRemoteRequest(SecurityCollectorManagerService::CMD_COLLECTOR_START, data, reply, option);
    EXPECT_EQ(result, SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, TestOnRemoteRequestWithCmd08, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> callback(new (std::nothrow) MockRemoteObject());

    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    data.WriteParcelable(&subscribeInfo);
    data.WriteRemoteObject(callback);
    int32_t result =
        g_service.OnRemoteRequest(SecurityCollectorManagerService::CMD_COLLECTOR_START, data, reply, option);
    EXPECT_EQ(result, SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, TestOnRemoteRequestWithCmd09, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    int32_t result =
        g_service.OnRemoteRequest(SecurityCollectorManagerService::CMD_COLLECTOR_STOP, data, reply, option);
    EXPECT_EQ(result, SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, TestOnRemoteRequestWithCmd10, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> callback = nullptr;

    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    data.WriteParcelable(&subscribeInfo);
    data.WriteRemoteObject(callback);
    int32_t result =
        g_service.OnRemoteRequest(SecurityCollectorManagerService::CMD_COLLECTOR_STOP, data, reply, option);
    EXPECT_EQ(result, SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, TestOnRemoteRequestWithCmd11, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> callback(new (std::nothrow) MockRemoteObject());

    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    data.WriteParcelable(&subscribeInfo);
    data.WriteRemoteObject(callback);
    int32_t result =
        g_service.OnRemoteRequest(SecurityCollectorManagerService::CMD_COLLECTOR_STOP, data, reply, option);
    EXPECT_EQ(result, SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, TestOnRemoteRequestWithCmd12, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int fd = 1;
    std::vector<std::u16string> args;
    g_service.Dump(fd, args);
    int32_t systemAbilityId = 0;
    const std::string& deviceId = "test";
    g_service.OnStop();
    g_service.OnAddSystemAbility(systemAbilityId, deviceId);
    g_service.OnRemoveSystemAbility(systemAbilityId, deviceId);

    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    int32_t result =
        g_service.OnRemoteRequest(SecurityCollectorManagerService::CMD_SECURITY_EVENT_QUERY, data, reply, option);
    EXPECT_EQ(result, SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, TestOnRemoteRequestWithCmd13, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    SecurityCollectorSubscribeInfo subscribeInfo{};

    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    data.WriteInt32(SecurityCollector::MAX_QUERY_EVENT_SIZE + 1);
    int32_t result =
        g_service.OnRemoteRequest(SecurityCollectorManagerService::CMD_SECURITY_EVENT_QUERY, data, reply, option);
    EXPECT_EQ(result, SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, TestOnRemoteRequestWithCmd14, TestSize.Level1)
{
    wptr<SecurityCollectorManagerService> service1
        = new SecurityCollectorManagerService(1, false);
    SecurityCollectorManagerService::SubscriberDeathRecipient testRecipient(service1);
    wptr<MockRemoteObject> remote1 = new MockRemoteObject();
    testRecipient.OnRemoteDied(remote1);
    testRecipient.OnRemoteDied(nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    SecurityCollector::SecurityEventRuler ruler{};

    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    data.WriteInt32(1);
    data.WriteParcelable(&ruler);
    int32_t result =
        g_service.OnRemoteRequest(SecurityCollectorManagerService::CMD_SECURITY_EVENT_QUERY, data, reply, option);
    EXPECT_NE(result, SecurityCollector::ErrorCode::TIME_OUT);
}

HWTEST_F(SecurityCollectorTest, TestLoaderLib002, TestSize.Level1)
{
    LibLoader loader("");
    EXPECT_EQ(loader.LoadLib(), RET_DLOPEN_LIB_FAIL);
    EXPECT_EQ(loader.CallGetCollector(), nullptr);
    LibLoader loader1("/system/etc/security_audit.cfg");
    EXPECT_EQ(loader1.LoadLib(), RET_DLOPEN_LIB_FAIL);
}

HWTEST_F(SecurityCollectorTest, QuerySecurityEventBatch01, TestSize.Level1)
{
    std::vector<SecurityEventRuler> rulers{};
    std::vector<SecurityEvent> events{};
    std::vector<int64_t> failedEventIds;
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_DENIED));
    EXPECT_EQ(g_service.QuerySecurityEventBatch(rulers, events, failedEventIds),
        SecurityCollector::ErrorCode::NO_PERMISSION);
}

HWTEST_F(SecurityCollectorTest, QuerySecurityEventBatch02, TestSize.Level1)
{
    std::vector<SecurityEventRuler> rulers{};
    std::vector<SecurityEvent> events{};
    std::vector<int64_t> failedEventIds;
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(DataCollection::GetInstance(), QuerySecurityEventBatch).WillOnce(
        Return(OHOS::Security::SecurityGuard::FAILED));
    EXPECT_NE(g_service.QuerySecurityEventBatch(rulers, events, failedEventIds),
        SecurityCollector::ErrorCode::SUCCESS);
}

HWTEST_F(SecurityCollectorTest, QuerySecurityEventBatch03, TestSize.Level1)
{
    std::vector<SecurityEventRuler> rulers{};
    std::vector<SecurityEvent> events{};
    std::vector<int64_t> failedEventIds;
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(DataCollection::GetInstance(), QuerySecurityEventBatch).WillOnce(Return(
        OHOS::Security::SecurityGuard::SUCCESS));
    EXPECT_EQ(g_service.QuerySecurityEventBatch(rulers, events, failedEventIds),
        SecurityCollector::ErrorCode::SUCCESS);
}

HWTEST_F(SecurityCollectorTest, HandleSecurityEventQueryBatchCmd01, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    data.WriteInt32(SecurityCollectorManagerService::CMD_SECURITY_EVENT_QUERY_BATCH);
    int32_t result = g_service.OnRemoteRequest(
        SecurityCollectorManagerService::CMD_SECURITY_EVENT_QUERY_BATCH, data, reply, option);
    EXPECT_EQ(result, SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, HandleSecurityEventQueryBatchCmd02, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    data.WriteUint32(1);
    SecurityEventRuler ruler(11111);
    data.WriteParcelable(&ruler);
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(DataCollection::GetInstance(), QuerySecurityEventBatch).WillOnce(Return(
        OHOS::Security::SecurityGuard::SUCCESS));
    int32_t result = g_service.OnRemoteRequest(
        SecurityCollectorManagerService::CMD_SECURITY_EVENT_QUERY_BATCH, data, reply, option);
    EXPECT_EQ(result, SecurityCollector::ErrorCode::SUCCESS);
}

HWTEST_F(SecurityCollectorTest, HandleSecurityEventQueryBatchCmd03, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    data.WriteUint32(SecurityCollector::MAX_QUERY_EVENT_SIZE + 1);
    int32_t result = g_service.OnRemoteRequest(
        SecurityCollectorManagerService::CMD_SECURITY_EVENT_QUERY_BATCH, data, reply, option);
    EXPECT_EQ(result, SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, HandleSecurityEventQueryBatchCmd04, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    int32_t result = g_service.OnRemoteRequest(
        SecurityCollectorManagerService::CMD_SECURITY_EVENT_QUERY_BATCH, data, reply, option);
    EXPECT_EQ(result, SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, HandleSecurityEventQueryBatchCmd05, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    data.WriteUint32(1);
    data.WriteInt32(0);
    int32_t result = g_service.OnRemoteRequest(
        SecurityCollectorManagerService::CMD_SECURITY_EVENT_QUERY_BATCH, data, reply, option);
    EXPECT_EQ(result, SecurityCollector::ErrorCode::BAD_PARAM);
}

HWTEST_F(SecurityCollectorTest, HandleSecurityEventQueryBatchCmd06, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    SecurityEventRuler ruler(11111);
    data.WriteInterfaceToken(ISecurityCollectorManager::GetDescriptor());
    data.WriteUint32(1);
    data.WriteParcelable(&ruler);
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(DataCollection::GetInstance(), QuerySecurityEventBatch).WillOnce(
        [](const std::vector<SecurityEventRuler> &rulers,
        std::vector<SecurityEvent> &events, std::vector<int64_t> &failedEventIds) {
            failedEventIds.push_back(rulers[0].GetEventId());
            return OHOS::Security::SecurityGuard::FAILED;
        }
    );
    int32_t result = g_service.OnRemoteRequest(
        SecurityCollectorManagerService::CMD_SECURITY_EVENT_QUERY_BATCH, data, reply, option);
    EXPECT_EQ(result, SecurityCollector::ErrorCode::SUCCESS);
    int32_t ret = 0;
    EXPECT_TRUE(reply.ReadInt32(ret));
    EXPECT_EQ(ret, OHOS::Security::SecurityGuard::READ_ERR);
    uint32_t eventSize = 0;
    EXPECT_TRUE(reply.ReadUint32(eventSize));
    EXPECT_EQ(eventSize, 0UL);
    uint32_t failedSize = 0;
    EXPECT_TRUE(reply.ReadUint32(failedSize));
    EXPECT_EQ(failedSize, 1UL);
    int64_t failedId = 0;
    EXPECT_TRUE(reply.ReadInt64(failedId));
    EXPECT_EQ(failedId, 11111);
}
}