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

#include "security_guard_data_collect_sa_test.h"

#include <thread>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fstream>
#include "directory_ex.h"
#include "file_ex.h"
#include "gmock/gmock.h"
#include "system_ability_definition.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "security_config_update_info.h"
#include "security_event_info.h"
#include "config_define.h"
#define private public
#define protected public
#include "accesstoken_kit.h"
#include "acquire_data_subscribe_manager.h"
#include "security_collector_run_manager.h"
#include "collector_manager.h"
#include "config_data_manager.h"
#include "data_collect_manager.h"
#include "data_format.h"
#include "database_manager.h"
#include "data_collect_manager_service.h"
#include "security_event_query_callback_proxy.h"
#include "security_event_ruler.h"
#include "security_collector_subscribe_info.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityGuardTest;
namespace OHOS {
    std::shared_ptr<Security::SecurityGuard::MockDataFormatInterface> DataFormat::instance_ = nullptr;
    std::shared_ptr<AccountSA::MockOsAccountManagerInterface> AccountSA::OsAccountManager::instance_ = nullptr;
    std::shared_ptr<Security::AccessToken::MockAccessTokenKitInterface>
        Security::AccessToken::AccessTokenKit::instance_ = nullptr;
    std::shared_ptr<Security::AccessToken::MockTokenIdKitInterface>
        Security::AccessToken::TokenIdKit::instance_ = nullptr;
    std::mutex Security::SecurityGuard::DataFormat::mutex_ {};
    std::mutex Security::AccessToken::AccessTokenKit::mutex_ {};
    std::mutex Security::AccessToken::TokenIdKit::mutex_ {};
}

namespace OHOS::Security::SecurityGuardTest {
const std::string &SECURITY_GUARD_EVENT_CFG_FILE = SECURITY_GUARD_EVENT_CFG_SOURCE;

void SecurityGuardDataCollectSaTest::SetUpTestCase()
{
}

void SecurityGuardDataCollectSaTest::TearDownTestCase()
{
    DataFormat::DelInterface();
    AccessToken::AccessTokenKit::DelInterface();
    AccessToken::TokenIdKit::DelInterface();
}

void SecurityGuardDataCollectSaTest::SetUp()
{
}

void SecurityGuardDataCollectSaTest::TearDown()
{
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestDumpWithInvalidFd, TestSize.Level0)
{
    int fd = -1;
    std::vector<std::u16string> args;
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);

    EXPECT_EQ(service.Dump(fd, args), BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestDumpWithInvalidArgs, TestSize.Level0)
{
    int fd = 1;
    std::vector<std::u16string> args;
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.Dump(fd, args), ERR_OK);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestDumpWithHelpCommand, TestSize.Level0)
{
    int fd = 1;
    std::vector<std::u16string> args = { u"-h" };
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.Dump(fd, args), ERR_OK);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestDumpWithOtherCommand, TestSize.Level0)
{
    int fd = 1;
    std::vector<std::u16string> args = { u"-s" };
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.Dump(fd, args), ERR_OK);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestDumpWithInvalidEventId01, TestSize.Level0)
{
    int fd = 1;
    std::vector<std::u16string> args = { u"-i", u"invalid" };
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.Dump(fd, args), BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestDumpWithInvalidEventId02, TestSize.Level0)
{
    int fd = 1;
    std::vector<std::u16string> args = { u"-i" };
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.Dump(fd, args), BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestDumpWithValidEventId, TestSize.Level0)
{
    int fd = 1;
    std::vector<std::u16string> args = { u"-i", u"12345" };
    EXPECT_CALL(DatabaseManager::GetInstance(), QueryRecentEventByEventId(_, _))
        .WillOnce(Return(SUCCESS));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.Dump(fd, args), ERR_OK);
}

HWTEST_F(SecurityGuardDataCollectSaTest, DumpEventInfo_Success, TestSize.Level0) {
    SecEvent secEvent;
    secEvent.eventId = 1;
    secEvent.date = "2022-01-01";
    secEvent.version = "1.0";

    EXPECT_CALL(DatabaseManager::GetInstance(), QueryRecentEventByEventId(1, _))
        .WillOnce(Return(SUCCESS));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    service.DumpEventInfo(1, 1);
}

HWTEST_F(SecurityGuardDataCollectSaTest, DumpEventInfo_QueryError, TestSize.Level0) {
    EXPECT_CALL(DatabaseManager::GetInstance(), QueryRecentEventByEventId(1, _))
        .WillOnce(Return(FAILED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    service.DumpEventInfo(1, 1);
}

HWTEST_F(SecurityGuardDataCollectSaTest, GetSecEventsFromConditions_NoTimeCondition, TestSize.Level0) {
    RequestCondition condition{};
    EXPECT_CALL(DatabaseManager::GetInstance(), QueryEventByEventId(_, _, _))
        .WillRepeatedly([] (std::string table, std::vector<int64_t> &eventIds,
            std::vector<SecEvent> &events) {
            SecEvent event {};
            event.eventId = 1;
            events.emplace_back(event);
            return SUCCESS;
        });
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    std::vector<SecEvent> events = service.GetSecEventsFromConditions(condition);
    EXPECT_EQ(events[0].eventId, 1);
}

HWTEST_F(SecurityGuardDataCollectSaTest, GetSecEventsFromConditions_WithTimeCondition, TestSize.Level0) {
    RequestCondition condition;
    condition.riskEvent = {};
    condition.auditEvent = {};
    condition.beginTime = "2022-01-01";
    condition.endTime = "2022-01-31";

    EXPECT_CALL(DatabaseManager::GetInstance(), QueryEventByEventIdAndDate(_, _, _, _, _))
        .WillRepeatedly([] (std::string table, std::vector<int64_t> &eventIds, std::vector<SecEvent> &events,
        std::string beginTime, std::string endTime) {
            SecEvent event {};
            event.eventId = 1;
            events.emplace_back(event);
            return SUCCESS;
        });
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    std::vector<SecEvent> events = service.GetSecEventsFromConditions(condition);
    EXPECT_EQ(events[0].eventId, 1);
}

HWTEST_F(SecurityGuardDataCollectSaTest, QueryEventByRuler_GetEventConfigError001, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillOnce(Return(false));
    sptr<SecurityEventQueryCallbackProxy> mockProxy = new (std::nothrow) SecurityEventQueryCallbackProxy(obj);
    SecurityCollector::SecurityEventRuler ruler;
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_FALSE(service.QueryEventByRuler(mockProxy, ruler));
}

HWTEST_F(SecurityGuardDataCollectSaTest, QueryEventByRuler_GetEventConfigError002, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillOnce(Return(false));
    sptr<SecurityEventQueryCallbackProxy> mockProxy = new (std::nothrow) SecurityEventQueryCallbackProxy(obj);
    SecurityCollector::SecurityEventRuler ruler;
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_CALL(*obj, SendRequest).Times(1);
    mockProxy->OnError("123");
    EXPECT_FALSE(service.QueryEventByRuler(mockProxy, ruler));
}

HWTEST_F(SecurityGuardDataCollectSaTest, QueryEventByRuler_QueryInDatabase, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);

    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillOnce([] (int64_t eventId, EventCfg &config) {
        config.eventType = 0;
        return true;
    });
    SecEvent event;
    event.eventId = 1;
    event.version = 1;
    event.content = "content";
    std::vector<SecEvent> events{event};
    EXPECT_CALL(DatabaseManager::GetInstance(), QueryEventByEventId(_, _)).WillRepeatedly(Return(true));
    sptr<SecurityEventQueryCallbackProxy> mockProxy = new (std::nothrow) SecurityEventQueryCallbackProxy(obj);
    SecurityCollector::SecurityEventRuler ruler;
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_TRUE(service.QueryEventByRuler(mockProxy, ruler));
}

HWTEST_F(SecurityGuardDataCollectSaTest, QueryEventByRuler_QueryInCollector, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillOnce([] (int64_t eventId, EventCfg &config) {
        config.eventType = 1;
        return true;
    });
    SecurityCollector::SecurityEvent event;
    event.eventId_ = 1;
    event.version_ = 1;
    event.content_ = "content";
    std::vector<SecurityCollector::SecurityEvent> events{event};
    EXPECT_CALL(SecurityCollector::CollectorManager::GetInstance(), QuerySecurityEvent(_, _)).WillOnce(Return(SUCCESS));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    sptr<SecurityEventQueryCallbackProxy> mockProxy = new (std::nothrow) SecurityEventQueryCallbackProxy(obj);
    SecurityCollector::SecurityEventRuler ruler;
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_TRUE(service.QueryEventByRuler(mockProxy, ruler));
}

HWTEST_F(SecurityGuardDataCollectSaTest, QueryEventByRuler_NotSupportType, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly([] (
        int64_t eventId, EventCfg &config) {
        config.eventType = 2;
        return true;
    });
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    sptr<SecurityEventQueryCallbackProxy> mockProxy = new (std::nothrow) SecurityEventQueryCallbackProxy(obj);
    SecurityCollector::SecurityEventRuler ruler;

    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_TRUE(service.QueryEventByRuler(mockProxy, ruler));
}

HWTEST_F(SecurityGuardDataCollectSaTest, QueryEventByRuler_BeginTimeEmpty, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly([] (
        int64_t eventId, EventCfg &config) {
        config.eventType = 2;
        return true;
    });
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(obj != nullptr);
    sptr<SecurityEventQueryCallbackProxy> mockProxy = new (std::nothrow) SecurityEventQueryCallbackProxy(obj);
    SecurityCollector::SecurityEventRuler ruler(2, "", "11", "tt");
    EXPECT_CALL(*obj, SendRequest).Times(1);

    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_TRUE(service.QueryEventByRuler(mockProxy, ruler));
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestPushDataCollectTask_NullProxy, TestSize.Level0)
{
    std::shared_ptr<std::promise<int32_t>> promise = std::make_shared<std::promise<int32_t>>();
    EXPECT_TRUE(promise != nullptr);
    sptr<MockRemoteObject> mockObj = nullptr;
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    service.PushDataCollectTask(mockObj, "conditions", "devId", promise);
    EXPECT_EQ(0, promise->get_future().get());
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestPushDataCollectTask_EmptyConditions, TestSize.Level0)
{
    std::shared_ptr<std::promise<int32_t>> promise = std::make_shared<std::promise<int32_t>>();
    EXPECT_TRUE(promise != nullptr);
    sptr<MockRemoteObject> mockObj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(mockObj != nullptr);
    EXPECT_CALL(*(DataFormat::GetInterface()), ParseConditions).WillOnce([]
        (std::string conditions, RequestCondition &reqCondition) {
            reqCondition = {};
        });
    EXPECT_CALL(*mockObj, SendRequest).Times(1);
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    ON_CALL(*mockObj, SendRequest)
        .WillByDefault([&service](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            service.OnRemoteRequest(code, data, reply, option);
            return SUCCESS;
        });
    service.PushDataCollectTask(mockObj, "", "devId", promise);
    EXPECT_EQ(0, promise->get_future().get());
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestPushDataCollectTask_ValidConditions01, TestSize.Level0)
{
    std::shared_ptr<std::promise<int32_t>> promise = std::make_shared<std::promise<int32_t>>();
    EXPECT_TRUE(promise != nullptr);
    EXPECT_CALL(*(DataFormat::GetInterface()), ParseConditions).WillOnce([]
        (std::string conditions, RequestCondition &reqCondition) {
            reqCondition.auditEvent = {1};
        });
    EXPECT_CALL(DatabaseManager::GetInstance(), QueryEventByEventId(_, _, _))
        .WillRepeatedly([] (std::string table, std::vector<int64_t> &eventIds,
            std::vector<SecEvent> &events) {
            SecEvent event {};
            event.eventId = 1;
            events.emplace_back(event);
            return SUCCESS;
        });
    sptr<MockRemoteObject> mockObj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(*mockObj, SendRequest).Times(1);
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    service.PushDataCollectTask(mockObj, "conditions", "devId", promise);
    EXPECT_EQ(1, promise->get_future().get());
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestPushDataCollectTask_ValidConditions02, TestSize.Level0)
{
    std::shared_ptr<std::promise<int32_t>> promise = std::make_shared<std::promise<int32_t>>();
    EXPECT_TRUE(promise != nullptr);
    sptr<MockRemoteObject> mockObj(new (std::nothrow) MockRemoteObject());
    EXPECT_TRUE(mockObj != nullptr);
    EXPECT_CALL(*(DataFormat::GetInterface()), ParseConditions).WillOnce([]
        (std::string conditions, RequestCondition &reqCondition) {
            reqCondition.auditEvent = {1};
        });
    EXPECT_CALL(DatabaseManager::GetInstance(), QueryEventByEventId(_, _, _))
        .WillRepeatedly([] (std::string table, std::vector<int64_t> &eventIds,
            std::vector<SecEvent> &events) {
            SecEvent event {};
            event.eventId = 1;
            return SUCCESS;
        });
    EXPECT_CALL(*mockObj, SendRequest).Times(1);
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    service.PushDataCollectTask(mockObj, "conditions", "devId", promise);
    EXPECT_EQ(0, promise->get_future().get());
}

HWTEST_F(SecurityGuardDataCollectSaTest, RequestDataSubmit_NoPermission, TestSize.Level0)
{
    int64_t eventId = 1;
    std::string version = "1.0";
    std::string time = "2022-01-01";
    std::string content = "content";

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillRepeatedly(
        Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    service.OnAddSystemAbility(RISK_ANALYSIS_MANAGER_SA_ID, "deviceId");
    service.tokenBucket_.fetch_add(1);
    int32_t result = service.RequestDataSubmit(eventId, version, time, content);
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, RequestDataSubmitAsync_NoPermission, TestSize.Level0)
{
    int64_t eventId = 1;
    std::string version = "1.0";
    std::string time = "2022-01-01";
    std::string content = "content";

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillRepeatedly(
        Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    service.OnAddSystemAbility(RISK_ANALYSIS_MANAGER_SA_ID, "deviceId");
    service.tokenBucket_.fetch_add(1);
    int32_t result = service.RequestDataSubmitAsync(eventId, version, time, content);
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, RequestDataSubmit_BadParam, TestSize.Level0)
{
    int64_t eventId = 1;
    std::string version = "1.0";
    std::string time = "2022-01-01";
    std::string content = "content";

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    EXPECT_CALL(*(DataFormat::GetInterface()), CheckRiskContent).WillOnce(Return(false));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    service.tokenBucket_.fetch_add(1);
    int32_t result = service.RequestDataSubmit(eventId, version, time, content);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, RequestDataSubmit_Success01, TestSize.Level0)
{
    int64_t eventId = 1;
    std::string version = "1.0";
    std::string time = "2022-01-01";
    std::string content = "content";

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    EXPECT_CALL(*(DataFormat::GetInterface()), CheckRiskContent).WillOnce(Return(true));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    service.tokenBucket_.fetch_add(1);
    int32_t result = service.RequestDataSubmit(eventId, version, time, content);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, RequestDataSubmit_Success02, TestSize.Level0)
{
    int64_t eventId = 1;
    std::string version = "1.0";
    std::string time = "2022-01-01";
    std::string content = "content";

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    EXPECT_CALL(*(DataFormat::GetInterface()), CheckRiskContent).WillOnce(Return(true));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    service.tokenBucket_.fetch_add(1);
    int32_t result = service.RequestDataSubmit(eventId, version, time, content);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, RequestRiskData01, TestSize.Level0)
{
    std::string devId = "devId";
    std::string eventList = "eventList";
    sptr<IRemoteObject> obj = nullptr;

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.RequestRiskData(devId, eventList, obj);
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, RequestRiskData02, TestSize.Level0)
{
    std::string devId = "devId";
    std::string eventList = "eventList";
    sptr<IRemoteObject> obj = nullptr;

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.RequestRiskData(devId, eventList, obj);
    service.OnRemoveSystemAbility(0, "dd");
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, RequestRiskData03, TestSize.Level0)
{
    std::string devId = "devId";
    std::string eventList = "eventList";
    sptr<IRemoteObject> obj = nullptr;

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(false));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.RequestRiskData(devId, eventList, obj);
    EXPECT_EQ(result, NO_SYSTEMCALL);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Subscribe01, TestSize.Level0)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.Subscribe(subscribeInfo, obj, "111");
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Unsubscribe01, TestSize.Level0)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> mockObj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.Unsubscribe(subscribeInfo, mockObj, "111");
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Subscribe02, TestSize.Level0)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(false));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.Subscribe(subscribeInfo, obj, "111");
    EXPECT_EQ(result, NO_SYSTEMCALL);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Unsubscribe02, TestSize.Level0)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> mockObj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(false));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.Unsubscribe(subscribeInfo, mockObj, "111");
    EXPECT_EQ(result, NO_SYSTEMCALL);
}

HWTEST_F(SecurityGuardDataCollectSaTest, InsertSubscribeRecord_Success, TestSize.Level0)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    AcquireDataSubscribeManager::GetInstance().StartClearEventCache();
    AcquireDataSubscribeManager::GetInstance().StopClearEventCache();
    AcquireDataSubscribeManager::GetInstance().DeInitDeviceId();
    AcquireDataSubscribeManager::GetInstance().DeInitEventQueue();
    AcquireDataSubscribeManager::GetInstance().StartTokenBucketTask();
    AcquireDataSubscribeManager::GetInstance().StopTokenBucketTask();
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, obj, "111");
    EXPECT_EQ(result, SUCCESS);
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(subscribeInfo.GetEvent().eventId, obj,
        "111");
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Publish_WithSubscribers, TestSize.Level0)
{
    SecurityCollector::Event event {
        .eventId = 1,
        .version = "version",
        .content = "content"
    };
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(
        [] (int64_t eventId, EventCfg &config) {
        return true;
    });
    EXPECT_CALL(*(DataFormat::GetInterface()), CheckRiskContent).WillOnce(Return(true)).WillOnce(Return(true));
    AcquireDataSubscribeManager::GetInstance().UploadEventTask(event);
    AcquireDataSubscribeManager::CollectorListener listener {};
    listener.OnNotify(event);
    listener.GetExtraInfo();
    constexpr size_t cacheSize = 64;
    SecurityGuard::SecEvent eve {
        .eventId = 1,
        .version = "version",
        .content = "content"
    };
    AcquireDataSubscribeManager::SecurityCollectorSubscriber sub(event);
    for (size_t i = 0; i < cacheSize + 1; i++) {
        AcquireDataSubscribeManager::GetInstance().events_.emplace_back(eve);
    }
    sub.OnNotify(event);
    EXPECT_TRUE(AcquireDataSubscribeManager::GetInstance().PublishEventToSub(event));
}

HWTEST_F(SecurityGuardDataCollectSaTest, Publish_NullProxy, TestSize.Level0)
{
    SecurityCollector::Event event2 {
        .eventId = 2,
        .version = "version",
        .content = "content",
        .extra = ""
    };
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo(event2);
    sptr<MockRemoteObject> obj = nullptr;
    EXPECT_CALL(DatabaseManager::GetInstance(), SubscribeDb).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(DatabaseManager::GetInstance(), UnSubscribeDb).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(
        [] (int64_t eventId, EventCfg &config) {
        config.dbTable = "risk_event";
        config.eventType = 0;
        config.prog = "security_guard";
        config.eventId = eventId;
        config.isBatchUpload = 0;
        return true;
    });
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, obj, "111");
    EXPECT_EQ(result, SUCCESS);
    EXPECT_TRUE(AcquireDataSubscribeManager::GetInstance().PublishEventToSub(event2));
    EXPECT_TRUE(AcquireDataSubscribeManager::GetInstance().PublishEventToSub(event2));
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(subscribeInfo.GetEvent().eventId, obj,
        "111");
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Publish_NotNullProxy, TestSize.Level0)
{
    SecurityCollector::Event event2 {
        .eventId = SecurityCollector::FILE_EVENTID,
        .version = "version",
        .content = "content",
        .extra = ""
    };
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo(event2);
    sptr<MockRemoteObject> mockObject(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(DatabaseManager::GetInstance(), SubscribeDb).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(DatabaseManager::GetInstance(), UnSubscribeDb).WillRepeatedly(Return(SUCCESS));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(
        [] (int64_t eventId, EventCfg &config) {
        config.dbTable = "risk_event";
        config.eventType = 0;
        config.prog = "security_guard";
        config.eventId = eventId;
        config.isBatchUpload = 0;
        return true;
    });
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, mockObject,
        "111");
    EXPECT_EQ(result, SUCCESS);
    EXPECT_TRUE(AcquireDataSubscribeManager::GetInstance().PublishEventToSub(event2));
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(subscribeInfo.GetEvent().eventId,
        mockObject, "111");
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Publish_DifferentEventId01, TestSize.Level0)
{
    SecurityCollector::Event event2 {
        .eventId = 1,
        .version = "version",
        .content = "content",
        .extra = ""
    };
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo(event2);
    sptr<MockRemoteObject> mockObj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(DatabaseManager::GetInstance(), SubscribeDb).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(DatabaseManager::GetInstance(), UnSubscribeDb).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetIsBatchUpload).WillRepeatedly(Return(false));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, mockObj, "111");
    EXPECT_EQ(result, SUCCESS);
    EXPECT_TRUE(AcquireDataSubscribeManager::GetInstance().PublishEventToSub(event2));
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(subscribeInfo.GetEvent().eventId,
        mockObj, "111");
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Publish_DifferentEventId02, TestSize.Level0)
{
    SecurityCollector::Event event2 {
        .eventId = SecurityCollector::PROCESS_EVENTID,
        .version = "version",
        .content = "content",
        .extra = ""
    };
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo(event2);
    sptr<MockRemoteObject> object(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(DatabaseManager::GetInstance(), SubscribeDb).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(DatabaseManager::GetInstance(), UnSubscribeDb).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetIsBatchUpload).WillRepeatedly(Return(false));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, object, "111");
    EXPECT_EQ(result, SUCCESS);
    EXPECT_TRUE(AcquireDataSubscribeManager::GetInstance().PublishEventToSub(event2));
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(subscribeInfo.GetEvent().eventId, object,
        "111");
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, Publish_DifferentEventId03, TestSize.Level0)
{
    SecurityCollector::Event event2 {
        .eventId = SecurityCollector::NETWORK_EVENTID,
        .version = "version",
        .content = "content",
        .extra = ""
    };
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo(event2);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(DatabaseManager::GetInstance(), SubscribeDb).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(DatabaseManager::GetInstance(), UnSubscribeDb).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetIsBatchUpload).WillRepeatedly(Return(false));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, obj, "111");
    EXPECT_EQ(result, SUCCESS);
    EXPECT_TRUE(AcquireDataSubscribeManager::GetInstance().PublishEventToSub(event2));
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(subscribeInfo.GetEvent().eventId, obj,
        "111");
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, AcquireDataSubscrSubscribeSc01, TestSize.Level0)
{
    AcquireDataSubscribeManager adsm {};
    SecurityCollector::Event event {
        .eventId = 111
    };
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    adsm.scSubscribeMap_.insert({111,
        std::make_shared<AcquireDataSubscribeManager::SecurityCollectorSubscriber>(event)});
    int result = adsm.SubscribeSc(111);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, AcquireDataSubscrSubscribeSc02, TestSize.Level0)
{
    AcquireDataSubscribeManager adsm {};
    SecurityCollector::Event event {
        .eventId = 111
    };
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(
        [] (int64_t eventId, EventCfg &config) {
        config.dbTable = "risk_event";
        config.eventType = 3;
        config.prog = "security_guard";
        return true;
    });
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillOnce(
        Return(false));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    int result = adsm.SubscribeSc(111);
    EXPECT_EQ(result, FAILED);
    result = adsm.UnSubscribeSc(111);
    EXPECT_EQ(result, FAILED);
}

HWTEST_F(SecurityGuardDataCollectSaTest, AcquireDataSubscrSubscribeSc03, TestSize.Level0)
{
    AcquireDataSubscribeManager adsm {};
    SecurityCollector::Event event {
        .eventId = 111
    };
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(
        [] (int64_t eventId, EventCfg &config) {
        config.dbTable = "risk_event";
        config.eventType = 3;
        config.prog = "";
        return true;
    });
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(SecurityCollector::CollectorManager::GetInstance(), Subscribe(_)).WillOnce(Return(FAILED));
    int result = adsm.SubscribeSc(111);
    EXPECT_EQ(result, FAILED);
    result = adsm.UnSubscribeSc(111);
    EXPECT_EQ(result, FAILED);
}

HWTEST_F(SecurityGuardDataCollectSaTest, AcquireDataSubscrSubscribeSc04, TestSize.Level0)
{
    AcquireDataSubscribeManager adsm {};
    SecurityCollector::Event event {
        .eventId = 111
    };
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(
        [] (int64_t eventId, EventCfg &config) {
        config.dbTable = "risk_event";
        config.eventType = 3;
        config.prog = "";
        return true;
    });
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(SecurityCollector::CollectorManager::GetInstance(), Subscribe(_)).WillOnce(Return(SUCCESS));
    int result = adsm.SubscribeSc(111);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_CALL(SecurityCollector::CollectorManager::GetInstance(), Unsubscribe(_)).WillOnce(
        Return(SUCCESS)).WillOnce(Return(FAILED));
    result = adsm.UnSubscribeSc(111);
    EXPECT_EQ(result, SUCCESS);
    AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecordOnRemoteDied(obj);
    auto subscriber = std::make_shared<AcquireDataSubscribeManager::SecurityCollectorSubscriber>(event);
    adsm.scSubscribeMap_.emplace(event.eventId, subscriber);
    result = adsm.UnSubscribeSc(111);
    EXPECT_EQ(result, FAILED);
}

HWTEST_F(SecurityGuardDataCollectSaTest, AcquireDataSubscrSubscribeSc05, TestSize.Level0)
{
    AcquireDataSubscribeManager adsm {};
    SecurityCollector::Event event {
        .eventId = 111
    };
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(
        [] (int64_t eventId, EventCfg &config) {
        return false;
    });
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    int result = adsm.SubscribeSc(111);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, AcquireDataSubscrSubscribeSc06, TestSize.Level0)
{
    AcquireDataSubscribeManager adsm {};
    SecurityCollector::Event event {
        .eventId = 111
    };
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(
        [] (int64_t eventId, EventCfg &config) {
        config.dbTable = "risk_event";
        config.eventType = 3;
        config.prog = "security_guard";
        return true;
    });
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillOnce(
        Return(false));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    int result = adsm.SubscribeSc(111);
    EXPECT_EQ(result, FAILED);

    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), UnsubscribeCollectors).WillOnce(
        Return(false));
    auto collectorListenner = std::make_shared<AcquireDataSubscribeManager::CollectorListener>();
    adsm.eventToListenner_.emplace(event.eventId, collectorListenner);
    result = adsm.UnSubscribeSc(111);
    EXPECT_EQ(result, FAILED);
}

HWTEST_F(SecurityGuardDataCollectSaTest, AcquireDataSubscrUnsubscribeSc01, TestSize.Level0)
{
    AcquireDataSubscribeManager adsm {};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(
        [] (int64_t eventId, EventCfg &config) {
        config.dbTable = "risk_event";
        config.eventType = 3;
        config.prog = "";
        return false;
    });
    int result = adsm.UnSubscribeSc(111);
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, QuerySecurityEvent, TestSize.Level0)
{
    SecurityCollector::SecurityEventRuler rule(11111);
    std::vector<SecurityCollector::SecurityEventRuler> rules {};
    rules.emplace_back(rule);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.QuerySecurityEvent(rules, obj, "");
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, QuerySecurityEvent01, TestSize.Level0)
{
    SecurityCollector::SecurityEventRuler rule(11111);
    std::vector<SecurityCollector::SecurityEventRuler> rules {};
    rules.emplace_back(rule);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(Return(false));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.QuerySecurityEvent(rules, obj, "");
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, QuerySecurityEvent02, TestSize.Level0)
{
    SecurityCollector::SecurityEventRuler rule(11111);
    std::vector<SecurityCollector::SecurityEventRuler> rules {};
    rules.emplace_back(rule);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(false));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.QuerySecurityEvent(rules, obj, "");
    EXPECT_EQ(result, NO_SYSTEMCALL);
}

HWTEST_F(SecurityGuardDataCollectSaTest, QuerySecurityEvent03, TestSize.Level0)
{
    SecurityCollector::SecurityEventRuler rule(11111);
    std::vector<SecurityCollector::SecurityEventRuler> rules {};
    rules.emplace_back(rule);
    sptr<MockRemoteObject> obj = nullptr;

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.QuerySecurityEvent(rules, obj, "");
    EXPECT_EQ(result, NULL_OBJECT);
}

HWTEST_F(SecurityGuardDataCollectSaTest, QuerySecurityEvent04, TestSize.Level0)
{
    SecurityCollector::SecurityEventRuler rule(11111);
    std::vector<SecurityCollector::SecurityEventRuler> rules {};
    rules.emplace_back(rule);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.QuerySecurityEvent(rules, obj, "");
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, QuerySecurityEvent05, TestSize.Level0)
{
    SecurityCollector::SecurityEventRuler rule(11111);
    std::vector<SecurityCollector::SecurityEventRuler> rules {};
    rules.emplace_back(rule);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(Return(false));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.QuerySecurityEvent(rules, obj, "securityGroup");
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, QuerySecurityEvent07, TestSize.Level0)
{
    SecurityCollector::SecurityEventRuler rule(11111);
    std::vector<SecurityCollector::SecurityEventRuler> rules {};
    rules.emplace_back(rule);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(
        [] (const std::string &groupName, EventGroupCfg &config) {
        config.eventList.insert(11111);
        config.permissionList.insert("testPermission");
        return true;
    });
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED)).WillOnce(
            Return(AccessToken::PermissionState::PERMISSION_DENIED)).WillOnce(
            Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true)).WillOnce(Return(false));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.QuerySecurityEvent(rules, obj, "securityGroup");
    EXPECT_EQ(result, SUCCESS);
    result = service.QuerySecurityEvent(rules, obj, "securityGroup");
    EXPECT_EQ(result, NO_PERMISSION);
    result = service.QuerySecurityEvent(rules, obj, "securityGroup");
    EXPECT_EQ(result, NO_SYSTEMCALL);
}

HWTEST_F(SecurityGuardDataCollectSaTest, CollectorStart01, TestSize.Level0)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.CollectorStart(subscribeInfo, obj);
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, CollectorStart02, TestSize.Level0)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(false));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.CollectorStart(subscribeInfo, obj);
    EXPECT_EQ(result, NO_SYSTEMCALL);
}

HWTEST_F(SecurityGuardDataCollectSaTest, CollectorStart03, TestSize.Level0)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(
        [] (int64_t eventId, EventCfg &config) {
        config.dbTable = "risk_event";
        config.eventType = 3;
        return true;
    });
    EXPECT_CALL(SecurityCollector::CollectorManager::GetInstance(), CollectorStart(_)).WillOnce(Return(FAILED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.CollectorStart(subscribeInfo, obj);
    EXPECT_EQ(result, FAILED);
}

HWTEST_F(SecurityGuardDataCollectSaTest, CollectorStart04, TestSize.Level0)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(
        [] (int64_t eventId, EventCfg &config) {
        config.dbTable = "risk_event";
        config.eventType = 3;
        config.prog = "security_guard";
        return true;
    });
    EXPECT_CALL(SecurityCollector::SecurityCollectorRunManager::GetInstance(),
        StartCollector(_)).WillOnce(Return(true));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.CollectorStart(subscribeInfo, obj);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, CollectorStop01, TestSize.Level0)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.CollectorStop(subscribeInfo, obj);
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, CollectorStop02, TestSize.Level0)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(false));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.CollectorStop(subscribeInfo, obj);
    EXPECT_EQ(result, NO_SYSTEMCALL);
}

HWTEST_F(SecurityGuardDataCollectSaTest, CollectorStop03, TestSize.Level0)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(
        [] (int64_t eventId, EventCfg &config) {
        config.dbTable = "risk_event";
        config.eventType = 3;
        return true;
    });
    EXPECT_CALL(SecurityCollector::CollectorManager::GetInstance(), CollectorStop(_)).WillOnce(Return(FAILED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.CollectorStop(subscribeInfo, obj);
    EXPECT_EQ(result, FAILED);
}

HWTEST_F(SecurityGuardDataCollectSaTest, CollectorStop04, TestSize.Level0)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(
        [] (int64_t eventId, EventCfg &config) {
        config.dbTable = "risk_event";
        config.eventType = 3;
        config.prog = "security_guard";
        return true;
    });
    EXPECT_CALL(SecurityCollector::SecurityCollectorRunManager::GetInstance(),
        StopCollector(_)).WillOnce(Return(true));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.CollectorStop(subscribeInfo, obj);
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, IsApiHasPermission01, TestSize.Level0)
{
    const std::string api = "testString";
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.IsCallerHasApiPermission(api);
    EXPECT_EQ(result, FAILED);
}

HWTEST_F(SecurityGuardDataCollectSaTest, ConfigUpdate01, TestSize.Level0)
{
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.ConfigUpdate(-1, "");
    EXPECT_EQ(result, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, ConfigUpdate02, TestSize.Level0)
{
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(false));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.ConfigUpdate(-1, "");
    EXPECT_EQ(result, NO_SYSTEMCALL);
}

HWTEST_F(SecurityGuardDataCollectSaTest, ConfigUpdate03, TestSize.Level0)
{
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.ConfigUpdate(-1, "");
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, ConfigUpdate04, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.ConfigUpdate(-1, SECURITY_GUARD_EVENT_CFG_FILE);
    EXPECT_EQ(result, FAILED);
}

HWTEST_F(SecurityGuardDataCollectSaTest, WriteRemoteFileToLocal01, TestSize.Level0)
{
    std::ofstream out("/data/test/unittest/resource/test.json");
    std::string errtmp = R"({
    "version":"001",
    "apps":""
    })";
    out << errtmp << std::endl;
    int32_t fd = open("/data/test/unittest/resource/test.json", O_RDONLY);

    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    std::string toPath = "/data/test/unittest/resource/";
    int32_t result = service.WriteRemoteFileToLocal(fd, toPath + "testFile.json");
    close(fd);
    EXPECT_EQ(result, FAILED);
}

HWTEST_F(SecurityGuardDataCollectSaTest, WriteRemoteFileToLocal02, TestSize.Level0)
{
    std::ofstream out("/data/test/unittest/resource/test.json");
    std::string errtmp = R"({
    "version":"001",
    "apps":""
    })";
    out << errtmp << std::endl;
    int32_t fd = 0;

    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    std::string toPath = "/data/test/unittest/resource/";
    int32_t result = service.WriteRemoteFileToLocal(fd, toPath + "testFile.json");
    EXPECT_EQ(result, FAILED);
}

HWTEST_F(SecurityGuardDataCollectSaTest, QueryEventConfig001, TestSize.Level0)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    std::string queryInfo;
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_DENIED));
    int32_t ret = service.QuerySecurityEventConfig(queryInfo);
    EXPECT_EQ(ret, NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, QueryEventConfig002, TestSize.Level0)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    std::string queryInfo;
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillOnce(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID)
        .WillOnce(Return(true));
    std::vector<EventCfg> emptyVector{};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetAllEventConfigs).WillOnce(Return(emptyVector));
    int32_t ret = service.QuerySecurityEventConfig(queryInfo);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, QueryEventConfig003, TestSize.Level0)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EventCfg cfg {};
    std::string queryInfo;
    std::vector<EventCfg> vector{};
    vector.emplace_back(cfg);
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetAllEventConfigs).WillOnce(Return(vector));
    int32_t ret = service.QueryEventConfig(queryInfo);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, ParseTrustListFile001, TestSize.Level0)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_FALSE(service.ParseTrustListFile(""));
}

HWTEST_F(SecurityGuardDataCollectSaTest, SubscribeScInSg, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    SecurityCollector::Event event {};
    event.eventId = 0;
    auto collectorListenner = std::make_shared<AcquireDataSubscribeManager::CollectorListener>();
    AcquireDataSubscribeManager::GetInstance().eventToListenner_.emplace(event.eventId, collectorListenner);
    int ret = AcquireDataSubscribeManager::GetInstance().SubscribeScInSg(0);
    EXPECT_CALL(*(DataFormat::GetInterface()), CheckRiskContent).WillOnce(Return(false)).WillOnce(Return(true));
    AcquireDataSubscribeManager::GetInstance().UploadEvent(event);
    AcquireDataSubscribeManager::GetInstance().UploadEvent(event);
    EXPECT_EQ(ret, SUCCESS);
    AcquireDataSubscribeManager::GetInstance().eventToListenner_.clear();
}

HWTEST_F(SecurityGuardDataCollectSaTest, SubscribeScInSg01, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillOnce(
        Return(true));
    int ret = AcquireDataSubscribeManager::GetInstance().SubscribeScInSg(1);
    EXPECT_EQ(ret, SUCCESS);
    AcquireDataSubscribeManager::GetInstance().eventToListenner_.clear();
}

HWTEST_F(SecurityGuardDataCollectSaTest, SubscribeScInSc, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    SecurityCollector::Event event {};
    event.eventId = 0;
    auto subscriber = std::make_shared<AcquireDataSubscribeManager::SecurityCollectorSubscriber>(event);
    AcquireDataSubscribeManager::GetInstance().scSubscribeMap_.emplace(event.eventId, subscriber);
    int ret = AcquireDataSubscribeManager::GetInstance().SubscribeScInSc(0);
    EXPECT_EQ(ret, SUCCESS);
    AcquireDataSubscribeManager::GetInstance().scSubscribeMap_.clear();
}

HWTEST_F(SecurityGuardDataCollectSaTest, SubscribeScInSc01, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(SecurityCollector::CollectorManager::GetInstance(), Subscribe).WillOnce(
        Return(SecurityCollector::SUCCESS));
    int ret = AcquireDataSubscribeManager::GetInstance().SubscribeScInSc(1);
    EXPECT_EQ(ret, SUCCESS);
    AcquireDataSubscribeManager::GetInstance().scSubscribeMap_.clear();
}

HWTEST_F(SecurityGuardDataCollectSaTest, IsEventGroupHasPermission, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillOnce(
        [] (const std::string &groupName, EventGroupCfg &config) {
        config.permissionList.insert("testPermission");
        return true;
    });

    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.IsEventGroupHasPermission("securityGroup", {11111});
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, InsertSubscribeMute, TestSize.Level0)
{
    EventMuteFilter subscribeMute {};
    subscribeMute.eventId = 111;
    EventMuteFilter subscribeMute1 {};
    subscribeMute1.eventId = 222;
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(
        [] (int64_t eventId, EventCfg &config) {
        config.dbTable = "risk_event";
        config.eventType = 3;
        config.prog = "security_guard";
        return true;
    });
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeMute(subscribeMute, "222");
    EXPECT_EQ(result, BAD_PARAM);
    result = AcquireDataSubscribeManager::GetInstance().CreatClient("securityGroup", "222", obj);
    EXPECT_EQ(result, SUCCESS);
    result = AcquireDataSubscribeManager::GetInstance().InsertSubscribeMute(subscribeMute, "222");
    EXPECT_EQ(result, SUCCESS);
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeMute(subscribeMute, "222");
    EXPECT_EQ(result, SUCCESS);
    result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeMute(subscribeMute1, "222");
    EXPECT_EQ(result, BAD_PARAM);
    result =  AcquireDataSubscribeManager::GetInstance().DestoryClient("securityGroup", "222");
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, RemoveSubscribeMute001, TestSize.Level0)
{
    EventMuteFilter subscribeMute {};
    EventMuteFilter subscribeMute1 {};
    subscribeMute.eventId = 111;
    int32_t result = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeMute(subscribeMute, "222");
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, CreatClient001, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<IPCObjectProxy::DeathRecipient> rec = nullptr;
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.CreatClient("", "111", obj);
    EXPECT_EQ(result, BAD_PARAM);
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(
        [] (const std::string &groupName, SecurityGuard::EventGroupCfg &config) {
            config.permissionList.insert("ohos.permission.QUERY_AUDIT_EVENT");
            config.eventList.insert(111);
            return true;
    });
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
    .WillOnce(Return(AccessToken::PermissionState::PERMISSION_DENIED)).WillOnce(Return(
        AccessToken::PermissionState::PERMISSION_DENIED)).WillOnce(Return(
        AccessToken::PermissionState::PERMISSION_GRANTED)).WillOnce(Return(
        AccessToken::PermissionState::PERMISSION_GRANTED)).WillOnce(Return(
        AccessToken::PermissionState::PERMISSION_GRANTED)).WillOnce(Return(
        AccessToken::PermissionState::PERMISSION_GRANTED)).WillOnce(Return(
        AccessToken::PermissionState::PERMISSION_GRANTED));
    result = service.CreatClient("securityGroup", "111", obj);
    EXPECT_EQ(result, NO_PERMISSION);
    result = service.CreatClient("auditGroup", "111", obj);
    EXPECT_EQ(result, NO_PERMISSION);
    EXPECT_CALL(*obj, AddDeathRecipient(_))
    .WillRepeatedly([&rec] (const sptr<IPCObjectProxy::DeathRecipient> &recipient) {
        rec = recipient;
        return true;
    });
    result = service.CreatClient("auditGroup", "111", nullptr);
    EXPECT_EQ(result, NULL_OBJECT);
    result = service.CreatClient("auditGroup", "111", obj);
    EXPECT_EQ(result, SUCCESS);
    result = service.CreatClient("auditGroup", "111", obj);
    EXPECT_EQ(result, BAD_PARAM);
    EXPECT_CALL(*obj, RemoveDeathRecipient).Times(1);
    result = service.DestoryClient("auditGroup", "111");
    EXPECT_EQ(result, SUCCESS);
    result = service.DestoryClient("auditGroup", "111");
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, CreatClient002, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    int32_t result = AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "111", obj);
    EXPECT_EQ(result, SUCCESS);
    result = AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "111", obj);
    EXPECT_EQ(result, BAD_PARAM);
    result = AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "222", obj);
    EXPECT_EQ(result, SUCCESS);
    result = AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "333", obj);
    EXPECT_EQ(result, CLIENT_EXCEED_PROCESS_LIMIT);
}

HWTEST_F(SecurityGuardDataCollectSaTest, CreatClient003, TestSize.Level0)
{
    AcquireDataSubscribeManager adsm {};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(
        [] (int64_t eventId, EventCfg &config) {
        config.dbTable = "risk_event";
        config.eventType = 3;
        config.prog = "security_guard";
        return true;
    });
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillOnce(
        Return(true));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), UnsubscribeCollectors).WillOnce(
        Return(true));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    int result = adsm.CreatClient("auditGroup", "111", obj);
    EXPECT_EQ(result, SUCCESS);
    result = adsm.InsertSubscribeRecord(111, "111");
    EXPECT_EQ(result, SUCCESS);
    result = adsm.RemoveSubscribeRecord(111, "111");
    EXPECT_EQ(result, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, DestoryClient001, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    int32_t result = service.DestoryClient("", "111");
    EXPECT_EQ(result, BAD_PARAM);
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(
        [] (const std::string &groupName, SecurityGuard::EventGroupCfg &config) {
            config.permissionList.insert("ohos.permission.QUERY_AUDIT_EVENT");
            config.eventList.insert(111);
            return true;
    });
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
    .WillOnce(Return(AccessToken::PermissionState::PERMISSION_DENIED)).WillOnce(Return(
        AccessToken::PermissionState::PERMISSION_DENIED)).WillOnce(Return(
        AccessToken::PermissionState::PERMISSION_GRANTED)).WillOnce(Return(
        AccessToken::PermissionState::PERMISSION_GRANTED)).WillOnce(Return(
        AccessToken::PermissionState::PERMISSION_GRANTED));
    result = service.DestoryClient("securityGroup", "111");
    EXPECT_EQ(result, NO_PERMISSION);
    result = service.DestoryClient("auditGroup", "111");
    EXPECT_EQ(result, NO_PERMISSION);
    result = service.DestoryClient("auditGroup", "111");
    EXPECT_EQ(result, BAD_PARAM);
    service.clientCallBacks_["111"] = obj;
    result = service.DestoryClient("auditGroup", "111");
    EXPECT_EQ(result, SUCCESS);
    service.clientCallBacks_["444"] = obj;
    result = service.DestoryClient("auditGroup", "444");
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, InsertMute001, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillOnce([] (int64_t eventId, EventCfg &config) {
        config.prog = "security_guard";
        return true;
    });
    AcquireDataSubscribeManager::GetInstance().eventFilter_ = nullptr;
    EventMuteFilter filter {};
    int32_t result = AcquireDataSubscribeManager::GetInstance().InsertMute(filter, "111");
    EXPECT_EQ(result, NULL_OBJECT);
}

HWTEST_F(SecurityGuardDataCollectSaTest, RemoveMute001, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(
        [] (int64_t eventId, EventCfg &config) {
        config.prog = "security_guard";
        return true;
    });
    AcquireDataSubscribeManager::GetInstance().eventFilter_ = nullptr;
    EventMuteFilter filter {};
    AcquireDataSubscribeManager::GetInstance().ClearEventCache();
    AcquireDataSubscribeManager::GetInstance().InitEventQueue();
    int32_t result = AcquireDataSubscribeManager::GetInstance().RemoveMute(filter, "111");
    EXPECT_EQ(result, NULL_OBJECT);
}

HWTEST_F(SecurityGuardDataCollectSaTest, IsEventGroupHasPublicPermission001, TestSize.Level0)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillOnce(
        [] (const std::string &groupName, EventGroupCfg &config) {
        config.eventList.insert(11111);
        config.permissionList.insert("testPermission");
        return true;
    });
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetAllEventIds).WillOnce(
        [] () {
        std::vector<int64_t> eventIds {};
        eventIds.emplace_back(11111);
        return eventIds;
    });
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillOnce(
        Return(true));
    AcquireDataSubscribeManager::GetInstance().SubscriberEventOnSgStart();
    int32_t result = service.IsEventGroupHasPermission("111", {222});
    EXPECT_EQ(result, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestQueryProcInfo, TestSize.Level0)
{
    SecurityCollector::SecurityEventRuler rule(11111);
    std::vector<SecurityCollector::SecurityEventRuler> rules{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillOnce(Return(true));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_DENIED));

    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.QuerySecurityEventById({rule}, obj, "auditGroup"), NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestQueryProcInfo002, TestSize.Level0)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(
        [] (const std::string &groupName, SecurityGuard::EventGroupCfg &config) {
            config.permissionList.insert("ohos.permission.QUERY_AUDIT_EVENT");
            config.eventList.insert(111);
            return true;
    });
    EXPECT_CALL(*obj, SendRequest).Times(1);

    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly([](int64_t eventId, EventCfg &config) {
        config.dbTable = "risk_event";
        config.eventType = 0;
        config.prog = "security_guard";
        return true;
    });

    SecurityCollector::SecurityEventRuler rule(11111);
    EXPECT_EQ(service.QuerySecurityEventById({rule}, obj, "auditGroup"), SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestQueryProcInfo003, TestSize.Level0)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(
        [] (const std::string &groupName, SecurityGuard::EventGroupCfg &config) {
            config.permissionList.insert("ohos.permission.QUERY_AUDIT_EVENT");
            config.eventList.insert(1011015023);
            return true;
    });
    EXPECT_CALL(*obj, SendRequest).Times(1);
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly([](int64_t eventId, EventCfg &config) {
        config.dbTable = "risk_event";
        config.eventType = 1;
        config.prog = "security_guard";
        return true;
    });

    SecurityCollector::SecurityEventRuler rule(1011015023);
    EXPECT_EQ(service.QuerySecurityEventById({rule}, obj, "auditGroup"), SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestQueryProcInfo004, TestSize.Level0)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(
        [] (const std::string &groupName, SecurityGuard::EventGroupCfg &config) {
            config.permissionList.insert("ohos.permission.QUERY_AUDIT_EVENT");
            config.eventList.insert(1011015023);
            return true;
    });
    EXPECT_CALL(*obj, SendRequest).Times(1);
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly([](int64_t eventId, EventCfg &config) {
        config.dbTable = "risk_event";
        config.eventType = 0;
        config.prog = "security_audit";
        return false;
    });

    SecurityCollector::SecurityEventRuler rule(1011015023);
    EXPECT_EQ(service.QuerySecurityEventById({rule}, obj, "auditGroup"), SUCCESS);
}


HWTEST_F(SecurityGuardDataCollectSaTest, TestQueryProcInfo005, TestSize.Level0)
{
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());

    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillOnce(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(
        [] (const std::string &groupName, SecurityGuard::EventGroupCfg &config) {
            config.permissionList.insert("ohos.permission.QUERY_AUDIT_EVENT");
            config.eventList.insert(1011015023);
            return true;
    });
    EXPECT_CALL(*obj, SendRequest).Times(1);

    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly([](int64_t eventId, EventCfg &config) {
        config.dbTable = "risk_event";
        config.eventType = 0;
        config.prog = "security_audit";
        return true;
    });
    SecurityCollector::SecurityEventRuler rule(1011015023);
    EXPECT_EQ(service.QuerySecurityEventById({rule}, obj, "auditGroup"), SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestQueryProcInfo06, TestSize.Level0)
{
    SecurityCollector::SecurityEventRuler rule(11111);
    std::vector<SecurityCollector::SecurityEventRuler> rules{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillOnce(Return(false));

    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.QuerySecurityEventById({rule}, obj, "auditGroup"), BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, AddFilter001, TestSize.Level0)
{
    SecurityGuard::EventMuteFilter info {};
    info.eventId = 11111;
    SecurityGuard::SecurityEventFilter filter(info);
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(
        [] (const std::string &groupName, EventGroupCfg &config) {
        config.eventList.insert(11111);
        config.permissionList.insert("testPermission");
        return true;
    });
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.AddFilter(info, "test_no_client"), NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, AddFilter002, TestSize.Level0)
{
    SecurityGuard::EventMuteFilter info {};
    info.eventId = 11111;
    SecurityGuard::SecurityEventFilter filter(info);
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(
        [] (const std::string &groupName, EventGroupCfg &config) {
        config.eventList.insert(11111);
        config.permissionList.insert("testPermission");
        return true;
    });
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.AddFilter(info, "test_no_client"), BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, RemoveFilter001, TestSize.Level0)
{
    SecurityGuard::EventMuteFilter info {};
    info.eventId = 11111;
    SecurityGuard::SecurityEventFilter filter(info);
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(
        [] (const std::string &groupName, EventGroupCfg &config) {
        config.eventList.insert(11111);
        config.permissionList.insert("testPermission");
        return true;
    });
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.RemoveFilter(info, "test_no_client"), NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, RemoveFilter002, TestSize.Level0)
{
    SecurityGuard::EventMuteFilter info {};
    info.eventId = 11111;
    SecurityGuard::SecurityEventFilter filter(info);
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(
        [] (const std::string &groupName, EventGroupCfg &config) {
        config.eventList.insert(11111);
        config.permissionList.insert("testPermission");
        return true;
    });
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.RemoveFilter(info, "test_no_client"), BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, NewSubscribe001, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(
        [] (const std::string &groupName, EventGroupCfg &config) {
        config.eventList.insert(11111);
        config.permissionList.insert("testPermission");
        return true;
    });
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.Subscribe(11111, "test_no_client"), BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, NewSubscribe002, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(
        [] (const std::string &groupName, EventGroupCfg &config) {
        config.eventList.insert(11111);
        config.permissionList.insert("testPermission");
        return true;
    });
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.Subscribe(11111, "test_no_client"), NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, NewUnsubscribe001, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(
        [] (const std::string &groupName, EventGroupCfg &config) {
        config.eventList.insert(11111);
        config.permissionList.insert("testPermission");
        return true;
    });
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.Unsubscribe(11111, "test_no_client"), BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaTest, NewUnsubscribe002, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(
        [] (const std::string &groupName, EventGroupCfg &config) {
        config.eventList.insert(11111);
        config.permissionList.insert("testPermission");
        return true;
    });
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken).WillOnce(
        Return(AccessToken::PermissionState::PERMISSION_DENIED));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    EXPECT_EQ(service.Unsubscribe(11111, "test_no_client"), NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestQueryCodeSign, TestSize.Level0)
{
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_DENIED));

    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    std::string result {};
    EXPECT_EQ(service.QueryCodeSignInfoByPath(1, 1, result), NO_PERMISSION);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestQueryCodeSign01, TestSize.Level0)
{
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), QuerySecurityEvent).WillOnce(Return(
        OHOS::Security::SecurityGuard::SUCCESS));
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    std::string result {};
    EXPECT_EQ(service.QueryCodeSignInfoByPath(1, 1, result), FAILED);
}

HWTEST_F(SecurityGuardDataCollectSaTest, TestQueryCodeSign02, TestSize.Level0)
{
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), QuerySecurityEvent).WillOnce(
        [] (const std::vector<SecurityEventRuler> rulers,
            std::vector<SecurityCollector::SecurityEvent> &events) {
            SecurityCollector::SecurityEvent event(111, "1.0", "test");
            events.emplace_back(event);
            return SUCCESS;
        });
    DataCollectManagerService service(DATA_COLLECT_MANAGER_SA_ID, true);
    std::string result {};
    EXPECT_EQ(service.QueryCodeSignInfoByPath(1, 1, result), SUCCESS);
}
}
