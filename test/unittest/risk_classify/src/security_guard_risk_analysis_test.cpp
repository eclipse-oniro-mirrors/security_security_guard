/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "security_guard_risk_analysis_test.h"
#include "gmock/gmock.h"
#define private public
#define protected public
#include "risk_analysis_manager_service.h"
#include "risk_analysis_manager_stub.h"
#undef private
#undef protected
#include "accesstoken_kit.h"
#include "tokenid_kit.h"
#include "ipc_skeleton.h"
using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityGuardTest;
namespace OHOS {
    std::shared_ptr<Security::AccessToken::MockTokenIdKitInterface>
        Security::AccessToken::TokenIdKit::instance_ = nullptr;
    std::mutex Security::AccessToken::TokenIdKit::mutex_ {};
    std::shared_ptr<Security::AccessToken::MockAccessTokenKitInterface>
        Security::AccessToken::AccessTokenKit::instance_ = nullptr;
    std::mutex Security::AccessToken::AccessTokenKit::mutex_ {};
    
class MockRemoteObject final : public IRemoteObject {
public:
    MockRemoteObject() : IRemoteObject(u"")
    {
    }
    int32_t GetObjectRefCount() { return 0; };
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) { return 0; };
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; };
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; };
    int Dump(int fd, const std::vector<std::u16string> &args) { return 0; };
};
}
namespace OHOS::Security::SecurityGuardTest {
RiskAnalysisManagerService riskAnalysisManagerService(RISK_ANALYSIS_MANAGER_SA_ID, true);
void SecurityGuardRiskAnalysisTest::SetUpTestCase()
{
}
void SecurityGuardRiskAnalysisTest::TearDownTestCase()
{
    AccessToken::AccessTokenKit::DelInterface();
    AccessToken::TokenIdKit::DelInterface();
}
void SecurityGuardRiskAnalysisTest::SetUp()
{
}
void SecurityGuardRiskAnalysisTest::TearDown()
{
}
 
HWTEST_F(SecurityGuardRiskAnalysisTest, IsApiHasPermission_ApiNotInMap, TestSize.Level1) {
    std::string api = "apiNotInMap";
    EXPECT_EQ(riskAnalysisManagerService.IsApiHasPermission(api), 1);
}

HWTEST_F(SecurityGuardRiskAnalysisTest, IsApiHasPermission_CallerNoPermission, TestSize.Level1) {
    const std::string api = "RequestSecurityModelResult";
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    int32_t result = riskAnalysisManagerService.IsApiHasPermission(api);
    EXPECT_EQ(result, NO_SYSTEMCALL);
}

HWTEST_F(SecurityGuardRiskAnalysisTest, IsApiHasPermission_NotSystemAppNoPermission, TestSize.Level1) {
    const std::string api = "RequestSecurityModelResult";
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_NATIVE));
    int32_t result = riskAnalysisManagerService.IsApiHasPermission(api);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardRiskAnalysisTest, IsApiHasPermission_PermissionDenied, TestSize.Level1) {
    const std::string api = "RequestSecurityModelResult";
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillRepeatedly(
        Return(AccessToken::PermissionState::PERMISSION_DENIED));
    int32_t result = riskAnalysisManagerService.IsApiHasPermission(api);
    EXPECT_EQ(result, 2);
}

HWTEST_F(SecurityGuardRiskAnalysisTest, IsApiHasPermission_Success, TestSize.Level1) {
    const std::string api = "RequestSecurityModelResult";
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillRepeatedly(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    int32_t result = riskAnalysisManagerService.IsApiHasPermission(api);
    EXPECT_EQ(result, 0);
}

HWTEST_F(SecurityGuardRiskAnalysisTest, SetModelState_Success, TestSize.Level1) {
    uint32_t modelId = 1;
    bool enable = true;
    int32_t result = riskAnalysisManagerService.SetModelState(modelId, enable);
    ASSERT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardRiskAnalysisTest, HandleSetModelState_001, TestSize.Level1)
{
    MessageParcel *data;
    MessageParcel *reply;
    data = new MessageParcel();
    reply = new MessageParcel();
    data->WriteBool(true);
    int32_t ret = riskAnalysisManagerService.HandleSetModelState(*data, *reply);
    ASSERT_EQ(ret, BAD_PARAM);
    delete data;
    delete reply;
}

HWTEST_F(SecurityGuardRiskAnalysisTest, HandleSetModelState_002, TestSize.Level1)
{
    MessageParcel *data;
    MessageParcel *reply;
    data = new MessageParcel();
    reply = new MessageParcel();
    data->WriteUint32(1);
    data->WriteBool(true);
    data->WriteUint32(2);
    int32_t ret = riskAnalysisManagerService.HandleSetModelState(*data, *reply);
    ASSERT_EQ(ret, SUCCESS);
    delete data;
    delete reply;
}

HWTEST_F(SecurityGuardRiskAnalysisTest, HandleStartModel_001, TestSize.Level1)
{
    MessageParcel *data;
    MessageParcel *reply;
    data = new MessageParcel();
    reply = new MessageParcel();
    int32_t ret = riskAnalysisManagerService.HandleStartModel(*data, *reply);
    ASSERT_EQ(ret, BAD_PARAM);
    delete data;
    delete reply;
}

HWTEST_F(SecurityGuardRiskAnalysisTest, HandleStartModel_002, TestSize.Level1)
{
    MessageParcel *data;
    MessageParcel *reply;
    data = new MessageParcel();
    reply = new MessageParcel();
    data->WriteUint32(2);
    int32_t ret = riskAnalysisManagerService.HandleStartModel(*data, *reply);
    ASSERT_EQ(ret, NO_PERMISSION);
    delete data;
    delete reply;
}

HWTEST_F(SecurityGuardRiskAnalysisTest, HandleGetSecurityModelResult_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(riskAnalysisManagerService.HandleGetSecurityModelResult(data, reply), BAD_PARAM);
}

HWTEST_F(SecurityGuardRiskAnalysisTest, HandleGetSecurityModelResult_002, TestSize.Level1)
{
    MessageParcel data;
    data.WriteUint32(1);
    data.WriteString("param");
    data.WriteRemoteObject(nullptr);
    MessageParcel reply;
    EXPECT_EQ(riskAnalysisManagerService.HandleGetSecurityModelResult(data, reply), BAD_PARAM);
}

HWTEST_F(SecurityGuardRiskAnalysisTest, HandleGetSecurityModelResult_003, TestSize.Level1)
{
    MessageParcel data;
    data.WriteUint32(1);
    data.WriteString("param");
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    data.WriteRemoteObject(obj);
    MessageParcel reply;
    EXPECT_EQ(riskAnalysisManagerService.HandleGetSecurityModelResult(data, reply),
        riskAnalysisManagerService.RequestSecurityModelResult("", 1, "param", obj));
}
}
