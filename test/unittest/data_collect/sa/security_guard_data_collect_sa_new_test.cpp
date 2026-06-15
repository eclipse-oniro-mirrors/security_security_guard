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

#include "security_guard_data_collect_sa_new_test.h"
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
namespace {
std::atomic<uint32_t> g_crucialTaskCount = 0;
}

namespace OHOS::Security::SecurityGuardTest {
void SecurityGuardDataCollectSaNewTest::SetUpTestCase() {}

void SecurityGuardDataCollectSaNewTest::TearDownTestCase()
{
    DataFormat::DelInterface();
    AccessToken::AccessTokenKit::DelInterface();
    AccessToken::TokenIdKit::DelInterface();
}

void SecurityGuardDataCollectSaNewTest::SetUp() {}

void SecurityGuardDataCollectSaNewTest::TearDown() {}

HWTEST_F(SecurityGuardDataCollectSaNewTest, CheckInsertMute_Test, TestSize.Level0)
{
    EventMuteFilter filter;
    filter.eventId = 111;
    filter.type = 1;
    filter.isInclude = true;
    filter.mutes = {"mute1"};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "muteclient", obj);
    int32_t ret = AcquireDataSubscribeManager::GetInstance().CheckInsertMute(filter, "nonexistent");
    EXPECT_EQ(ret, BAD_PARAM);
    ret = AcquireDataSubscribeManager::GetInstance().CheckInsertMute(filter, "muteclient");
    EXPECT_EQ(ret, SUCCESS);
    ret = AcquireDataSubscribeManager::GetInstance().InsertSubscribeMute(filter, "muteclient");
    EXPECT_EQ(ret, SUCCESS);
    ret = AcquireDataSubscribeManager::GetInstance().CheckInsertMute(filter, "muteclient");
    EXPECT_EQ(ret, BAD_PARAM);
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "muteclient");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, InsertSubscribeRecord_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillRepeatedly(Return(SUCCESS));
    sptr<MockRemoteObject> obj1(new (std::nothrow) MockRemoteObject());
    sptr<MockRemoteObject> obj2(new (std::nothrow) MockRemoteObject());
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "sdk_client", obj1);
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "sdk_client2", obj2);
    AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(111, "sdk_client");
    int32_t ret = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(111, "sdk_client");
    EXPECT_EQ(ret, SUCCESS);
    ret = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(222, "sdk_client2");
    EXPECT_EQ(ret, SUCCESS);
    ret = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(111, "sdk_client");
    EXPECT_EQ(ret, SUCCESS);
    ret = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(222, "sdk_client2");
    EXPECT_EQ(ret, SUCCESS);
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "sdk_client");
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "sdk_client2");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, RemoveSubscribeRecord_Callback_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillRepeatedly(Return(SUCCESS));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo;
    auto &mgr = AcquireDataSubscribeManager::GetInstance();
    int32_t ret = mgr.InsertSubscribeRecord(subscribeInfo, obj, "callback_client");
    EXPECT_EQ(ret, SUCCESS);
    ret = mgr.RemoveSubscribeRecord(subscribeInfo.GetEvent().eventId, "callback_client");
    EXPECT_EQ(ret, SUCCESS);
    ret = mgr.RemoveSubscribeRecord(999, obj, "callback_client");
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, RemoveSubscribeRecordOnRemoteDied_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(),
        UnsubscribeCollectors).WillRepeatedly(Return(SUCCESS));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo;
    auto &mgr = AcquireDataSubscribeManager::GetInstance();
    int32_t ret = mgr.InsertSubscribeRecord(subscribeInfo, obj, "died_client");
    EXPECT_EQ(ret, SUCCESS);
    mgr.RemoveSubscribeRecordOnRemoteDied(obj);
    mgr.RemoveSubscribeRecordOnRemoteDied(nullptr);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, SubscriberEventOnSgStart_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetAllEventIds).WillRepeatedly([]() {
        std::vector<int64_t> ids;
        ids.push_back(111);
        return ids;
    });
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &eventCfg) {
            eventCfg.collectOnStart = 1;
            return true;
        });
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillRepeatedly(Return(SUCCESS));
    AcquireDataSubscribeManager::GetInstance().SubscriberEventOnSgStart();
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, HasStickyEventReported_Test, TestSize.Level0)
{
    bool reported = AcquireDataSubscribeManager::GetInstance().HasStickyEventReported(111, "sticky_client");
    EXPECT_FALSE(reported);
    AcquireDataSubscribeManager::GetInstance().MarkStickyEventReported(111, "sticky_client");
    reported = AcquireDataSubscribeManager::GetInstance().HasStickyEventReported(111, "sticky_client");
    EXPECT_TRUE(reported);
    reported = AcquireDataSubscribeManager::GetInstance().HasStickyEventReported(999, "sticky_client");
    EXPECT_FALSE(reported);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, InsertMute_ConfigError_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillOnce(Return(false));
    EventMuteFilter filter;
    int32_t ret = AcquireDataSubscribeManager::GetInstance().InsertMute(filter, "test_client");
    EXPECT_EQ(ret, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, RemoveMute_ConfigError_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillOnce(Return(false));
    EventMuteFilter filter;
    int32_t ret = AcquireDataSubscribeManager::GetInstance().RemoveMute(filter, "test_client");
    EXPECT_EQ(ret, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, RemoveSubscribeMute_EventIdNotExist_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "mutetest", obj);
    EventMuteFilter filter;
    filter.eventId = 999;
    filter.type = 1;
    filter.isInclude = true;
    int32_t ret = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeMute(filter, "mutetest");
    EXPECT_EQ(ret, BAD_PARAM);
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "mutetest");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, PublishEventToSub_StickyEvent_Test, TestSize.Level0)
{
    SecurityCollector::Event event{
        .eventId = 1, .version = "version", .content = "content", .eventSubscribes = {"sticky_client2"}};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &eventCfg) {
            eventCfg.isSticky = 1;
            eventCfg.eventType = static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL);
            eventCfg.prog = "security_guard";
            return true;
    });
    EXPECT_CALL(*(DataFormat::GetInterface()), CheckRiskContent).WillRepeatedly(Return(true));
    sptr<MockRemoteObject> mockObj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID).WillRepeatedly(Return(true));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(),
        SubscribeCollectorsBySticky).WillRepeatedly(Return(FAILED));
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "sticky_client2");
    AcquireDataSubscribeManager::GetInstance().sessionsMap_.clear();
    AcquireDataSubscribeManager::GetInstance().eventToListenner_.clear();
    AcquireDataSubscribeManager::GetInstance().reportedStickyEvents_.clear();
    AcquireDataSubscribeManager::GetInstance().eventFilter_ = nullptr;
    int32_t ret = AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "sticky_client2", mockObj);
    EXPECT_EQ(ret, SUCCESS);
    ret = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(event.eventId, "sticky_client2");
    EXPECT_EQ(ret, 1);
    bool publishRet = AcquireDataSubscribeManager::GetInstance().PublishEventToSub(event);
    EXPECT_TRUE(publishRet);
    publishRet = AcquireDataSubscribeManager::GetInstance().PublishEventToSub(event);
    EXPECT_TRUE(publishRet);
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "sticky_client2");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, IsExceedLimited_GlobalLimit_Test, TestSize.Level0)
{
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(Return(true));
    for (int i = 0; i < 16; i++) {
        std::string clientId = "limit_client_" + std::to_string(i);
        int32_t ret = AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", clientId);
    }
    AcquireDataSubscribeManager::GetInstance().sessionsMap_.clear();
    for (int i = 0; i < 16; i++) {
        std::string clientId = "limit_client_" + std::to_string(i);
        int32_t ret = AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", clientId, obj);
        if (i < 2) {
            EXPECT_EQ(ret, SUCCESS);
        } else {
            EXPECT_EQ(ret, CLIENT_EXCEED_PROCESS_LIMIT);
        }
    }
    AcquireDataSubscribeManager::GetInstance().sessionsMap_.clear();
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, InsertMute_SetEventFilterFail_Test, TestSize.Level0)
{
    EventMuteFilter filter;
    filter.eventId = 1;
    filter.type = 1;
    filter.isInclude = true;
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillOnce(Return(true));
    int32_t ret = AcquireDataSubscribeManager::GetInstance().InsertMute(filter, "mute_fail_client");
    EXPECT_EQ(ret, NULL_OBJECT);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, InsertSubscribeRecord_DuplicateEventId_Test, TestSize.Level0)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, obj, "dup_test_client");
    int32_t ret =
        AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, obj, "dup_test_client");
    EXPECT_EQ(ret, SUCCESS);
    AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(subscribeInfo.GetEvent().eventId,
                                                                     "dup_test_client");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, InsertSubscribeRecord_SubscribeScFail_Test, TestSize.Level0)
{
    SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{};
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &eventCfg) {
            eventCfg.eventType = static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL);
            eventCfg.prog = "security_guard";
            return true;
        });
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillOnce(Return(FAILED));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID).WillRepeatedly(Return(true));
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "subscribe_fail_client");
    int32_t ret =
        AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(subscribeInfo, obj, "subscribe_fail_client");
    EXPECT_EQ(ret, FAILED);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, InsertSubscribeRecord_Simple_Duplicate_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "simple_client", obj);
    int32_t ret = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(100, "simple_client");
    EXPECT_EQ(ret, SUCCESS);
    ret = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(100, "simple_client");
    EXPECT_EQ(ret, SUCCESS);
    AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(100, "simple_client");
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "simple_client");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, RemoveSubscribeRecord_Simple_OtherClientSubscribed_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    sptr<MockRemoteObject> obj1(new (std::nothrow) MockRemoteObject());
    sptr<MockRemoteObject> obj2(new (std::nothrow) MockRemoteObject());
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(Return(true));
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "simple_other_client1", obj1);
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "simple_other_client2", obj2);
    AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(200, "simple_other_client1");
    AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(200, "simple_other_client2");
    int32_t ret = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(200, "simple_other_client1");
    EXPECT_EQ(ret, SUCCESS);
    AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(200, "simple_other_client2");
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "simple_other_client1");
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "simple_other_client2");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, RemoveSubscribeRecord_Simple_NotFoundEventId_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "simple_not_found_client", obj);
    AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(999, "simple_not_found_client");
    int32_t ret = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(999, "simple_not_found_client");
    EXPECT_EQ(ret, SUCCESS);
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "simple_not_found_client");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, InsertSubscribeRecord_WithEventFilters_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID).WillRepeatedly(Return(true));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "with_filters_client", obj);
    EventMuteFilter muteFilter;
    muteFilter.eventId = 100;
    muteFilter.type = 1;
    muteFilter.isInclude = true;
    AcquireDataSubscribeManager::GetInstance().sessionsMap_["with_filters_client"]->eventFilters[100].push_back(
        muteFilter);
    int32_t ret = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(100, "with_filters_client");
    EXPECT_EQ(ret, SUCCESS);
    AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(100, "with_filters_client");
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "with_filters_client");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, RemoveSubscribeRecord_UnsubscribeScFail_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &eventCfg) {
            eventCfg.eventType = static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL);
            eventCfg.prog = "security_guard";
            return true;
        });
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(),
        UnsubscribeCollectors).WillRepeatedly(Return(FAILED));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "unsubscribe_fail_client", obj);
    AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(300, "unsubscribe_fail_client");
    int32_t ret = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(300, "unsubscribe_fail_client");
    EXPECT_EQ(ret, FAILED);
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "unsubscribe_fail_client");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, RemoveSubscribeRecord_SessionEmpty_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(),
        UnsubscribeCollectors).WillRepeatedly(Return(SUCCESS));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "session_empty_client", obj);
    AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(400, "session_empty_client");
    int32_t ret = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(400, "session_empty_client");
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_TRUE(AcquireDataSubscribeManager::GetInstance().sessionsMap_.at("session_empty_client")->subEvents.empty());
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "session_empty_client");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, InsertMute_GetConfigError_Test, TestSize.Level0)
{
    EventMuteFilter filter;
    filter.eventId = 1;
    filter.type = 1;
    filter.isInclude = true;
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(false));
    int32_t ret = AcquireDataSubscribeManager::GetInstance().InsertMute(filter, "get_config_error_client");
    EXPECT_EQ(ret, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, InsertSubscribeRecord_SubscribeScFail_Branch_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &eventCfg) {
            eventCfg.eventType = static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL);
            eventCfg.prog = "security_guard";
            return true;
        });
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillRepeatedly(Return(FAILED));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "subscribe_fail_branch_client", obj);
    AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(500, "subscribe_fail_branch_client");
    int32_t ret = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(500, "subscribe_fail_branch_client");
    EXPECT_EQ(ret, FAILED);
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "subscribe_fail_branch_client");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, RemoveSubscribeRecord_OtherClientNotSubscribed_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(),
        UnsubscribeCollectors).WillRepeatedly(Return(SUCCESS));
    sptr<MockRemoteObject> obj1(new (std::nothrow) MockRemoteObject());
    sptr<MockRemoteObject> obj2(new (std::nothrow) MockRemoteObject());
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "remove_not_subscribed_client1", obj1);
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "remove_not_subscribed_client2", obj2);
    AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(600, "remove_not_subscribed_client1");
    int32_t ret =
        AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(600, "remove_not_subscribed_client1");
    EXPECT_EQ(ret, SUCCESS);
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "remove_not_subscribed_client1");
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "remove_not_subscribed_client2");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, InsertSubscribeRecord_ClientNotFound_Test, TestSize.Level0)
{
    int32_t ret = AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(700, "insert_not_found_client");
    EXPECT_EQ(ret, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, PublishEventToSub_GetConfigFail_Test, TestSize.Level0)
{
    SecurityCollector::Event event{.eventId = 1, .version = "version", .content = "content"};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(false));
    bool ret = AcquireDataSubscribeManager::GetInstance().PublishEventToSub(event);
    EXPECT_FALSE(ret);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, PublishEventToSub_SetCallingUidsFail_Test, TestSize.Level0)
{
    SecurityCollector::Event event{.eventId = 1, .version = "version", .content = "content"};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "set_calling_uids_fail_client", obj);
    AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(1, "set_calling_uids_fail_client");
    AcquireDataSubscribeManager::GetInstance().eventFilter_ = nullptr;
    bool ret = AcquireDataSubscribeManager::GetInstance().PublishEventToSub(event);
    EXPECT_TRUE(ret);
    AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(1, "set_calling_uids_fail_client");
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "set_calling_uids_fail_client");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, PublishEventToSub_NoSessionMatch_Test, TestSize.Level0)
{
    SecurityCollector::Event event{.eventId = 1, .version = "version", .content = "content"};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    bool ret = AcquireDataSubscribeManager::GetInstance().PublishEventToSub(event);
    EXPECT_TRUE(ret);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, RemoveMute_SubEventNotExist_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &eventCfg) {
            if (eventId == 900) {
                return false;
            }
            return true;
        });
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "remove_not_exist_client", obj);
    EventMuteFilter filter;
    filter.eventId = 900;
    filter.type = 1;
    filter.isInclude = true;
    AcquireDataSubscribeManager::GetInstance().sessionsMap_["remove_not_exist_client"]->eventFilters[900].push_back(
        filter);
    int32_t ret = AcquireDataSubscribeManager::GetInstance().RemoveMute(filter, "remove_not_exist_client");
    EXPECT_EQ(ret, BAD_PARAM);
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "remove_not_exist_client");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, RemoveMute_FilterNotFound_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &eventCfg) {
            if (eventId == 1000) {
                eventCfg.eventType = static_cast<uint32_t>(EventTypeEnum::NORMALE_COLL);
                eventCfg.prog = "security_guard";
                return true;
            }
            return false;
        });
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "filter_not_found_client", obj);
    AcquireDataSubscribeManager::GetInstance().sessionsMap_["filter_not_found_client"]->subEvents.insert(1000);
    EventMuteFilter filter;
    filter.eventId = 1000;
    filter.type = 1;
    filter.isInclude = true;
    AcquireDataSubscribeManager::GetInstance().eventFilter_ = nullptr;
    int32_t ret = AcquireDataSubscribeManager::GetInstance().RemoveMute(filter, "filter_not_found_client");
    EXPECT_EQ(ret, NULL_OBJECT);
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "filter_not_found_client");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, InitUserId_GetForegroundFail_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillRepeatedly(Return(SUCCESS));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "init_user_id_client", obj);
    AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(1100, "init_user_id_client");
    AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(1100, "init_user_id_client");
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "init_user_id_client");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, NotifySub_NullCallback_Test, TestSize.Level0)
{
    SecurityCollector::Event event{.eventId = 1200, .version = "version", .content = "content"};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "null_callback_client", obj);
    AcquireDataSubscribeManager::GetInstance().sessionsMap_["null_callback_client"]->callback = nullptr;
    AcquireDataSubscribeManager::GetInstance().sessionsMap_["null_callback_client"]->subEvents.insert(1200);
    AcquireDataSubscribeManager::GetInstance().eventFilter_ = nullptr;
    bool ret = AcquireDataSubscribeManager::GetInstance().PublishEventToSub(event);
    EXPECT_TRUE(ret);
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "null_callback_client");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, UploadEvent_CrucialTaskFull_Test, TestSize.Level0)
{
    SecurityCollector::Event event{.eventId = 1, .version = "version", .content = "content"};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    g_crucialTaskCount.store(6000);
    AcquireDataSubscribeManager::GetInstance().UploadEvent(event);
    g_crucialTaskCount.store(0);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, SubscriberEventOnScStart_SubscribeFail_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetAllEventIds).WillRepeatedly(Return(std::vector<int64_t>{1, 2, 3}));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillRepeatedly(Return(FAILED));
    AcquireDataSubscribeManager::GetInstance().SubscriberEventOnSgStart();
    EXPECT_FALSE(AcquireDataSubscribeManager::GetInstance().eventToListenner_.empty());
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, SubscriberEventOnScStart_ListenerNull_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetAllEventIds).WillRepeatedly(Return(std::vector<int64_t>{1, 2, 3}));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillRepeatedly(Return(SUCCESS));
    auto &mgr = AcquireDataSubscribeManager::GetInstance();
    auto originalListener = mgr.collectorListener_;
    mgr.collectorListener_ = nullptr;
    mgr.SubscriberEventOnSgStart();
    mgr.collectorListener_ = originalListener;
    EXPECT_FALSE(AcquireDataSubscribeManager::GetInstance().eventToListenner_.empty());
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, SubscriberEventOnSgStart_FilterNull_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetAllEventIds).WillRepeatedly(Return(std::vector<int64_t>{1, 2, 3}));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillRepeatedly(Return(SUCCESS));
    auto &mgr = AcquireDataSubscribeManager::GetInstance();
    mgr.eventFilter_ = nullptr;
    mgr.SubscriberEventOnSgStart();
    EXPECT_FALSE(AcquireDataSubscribeManager::GetInstance().eventToListenner_.empty());
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, GetAuditClientSessionMap_SessionCountExceed_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID).WillRepeatedly(Return(true));
    int successCount = 0;
    for (int i = 0; i < 20; i++) {
        sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
        std::string clientId = "session_exceed_client_" + std::to_string(i);
        int32_t ret = AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", clientId, obj);
        if (ret == SUCCESS) {
            successCount++;
        } else {
            SGLOGE("Create client %{public}s failed, ret: %{public}d", clientId.c_str(), ret);
        }
    }
    auto &mgr = AcquireDataSubscribeManager::GetInstance();
    EXPECT_EQ(static_cast<size_t>(successCount), 1);
    for (int i = 0; i < 20; i++) {
        std::string clientId = "session_exceed_client_" + std::to_string(i);
        mgr.DestoryClient("auditGroup", clientId);
    }
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, GetAuditClientSessionMap_SamePidExceed_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID).WillRepeatedly(Return(true));
    for (int i = 0; i < 3; i++) {
        sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
        std::string clientId = "same_pid_client_" + std::to_string(i);
        AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", clientId, obj);
    }
    auto &mgr = AcquireDataSubscribeManager::GetInstance();
    const auto &sessionMap = mgr.GetAuditClientSessionMap();
    EXPECT_EQ(sessionMap.size(), 2u);
    for (int i = 0; i < 3; i++) {
        std::string clientId = "same_pid_client_" + std::to_string(i);
        mgr.DestoryClient("auditGroup", clientId);
    }
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, StartClearEventCache_IsStopTrue_Test, TestSize.Level0)
{
    AcquireDataSubscribeManager::GetInstance().StartClearEventCache();
    AcquireDataSubscribeManager::GetInstance().isStopClearCache_ = true;
    AcquireDataSubscribeManager::GetInstance().StartClearEventCache();
    AcquireDataSubscribeManager::GetInstance().isStopClearCache_ = false;
    AcquireDataSubscribeManager::GetInstance().StartClearEventCache();
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, UploadEventToStore_QueueNotNull_Test, TestSize.Level0)
{
    SecurityCollector::Event event{.eventId = 1, .version = "version", .content = "content"};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    AcquireDataSubscribeManager::GetInstance().InitEventQueue();
    AcquireDataSubscribeManager::GetInstance().UploadEventToStore(event);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, UnSubscribeSc_GetConfigError_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(false));
    int32_t ret = AcquireDataSubscribeManager::GetInstance().UnSubscribeSc(1);
    EXPECT_EQ(ret, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, UnSubscribeSc_NotSubscribeColl_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &eventCfg) {
            eventCfg.eventType = static_cast<uint32_t>(EventTypeEnum::NORMALE_COLL);
            eventCfg.prog = "test";
            return true;
        });
    int32_t ret = AcquireDataSubscribeManager::GetInstance().UnSubscribeSc(1);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, SubscribeSc_GetConfigError_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(false));
    int32_t ret = AcquireDataSubscribeManager::GetInstance().SubscribeSc(1);
    EXPECT_EQ(ret, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, SubscribeSc_NotSubscribeColl_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &eventCfg) {
            eventCfg.eventType = static_cast<uint32_t>(EventTypeEnum::NORMALE_COLL);
            eventCfg.prog = "test";
            return true;
        });
    int32_t ret = AcquireDataSubscribeManager::GetInstance().SubscribeSc(1);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, UploadEventToStore_NullDbQueue_Test, TestSize.Level0)
{
    AcquireDataSubscribeManager::GetInstance().DeInitEventQueue();
    SecurityCollector::Event event{.eventId = 1, .version = "version", .content = "content"};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    AcquireDataSubscribeManager::GetInstance().UploadEventToStore(event);
    AcquireDataSubscribeManager::GetInstance().InitEventQueue();
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, UploadEventToStore_TaskCountLimit_Test, TestSize.Level0)
{
    AcquireDataSubscribeManager::GetInstance().InitEventQueue();
    SecurityCollector::Event event{.eventId = 1, .version = "version", .content = "content"};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    for (int i = 0; i < 64; i++) {
        AcquireDataSubscribeManager::GetInstance().UploadEventToStore(event);
    }
    AcquireDataSubscribeManager::GetInstance().DeInitEventQueue();
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, BatchUploadEvent_QueueNull_Test, TestSize.Level0)
{
    AcquireDataSubscribeManager::GetInstance().DeInitEventQueue();
    SecurityCollector::Event event{.eventId = 1, .version = "version", .content = "content"};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    int32_t ret = AcquireDataSubscribeManager::GetInstance().BatchUploadEvent(event);
    EXPECT_EQ(ret, SUCCESS);
    AcquireDataSubscribeManager::GetInstance().InitEventQueue();
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, UploadEventImmediately_QueueNull_Test, TestSize.Level0)
{
    AcquireDataSubscribeManager::GetInstance().DeInitEventQueue();
    SecurityCollector::Event event{.eventId = 1, .version = "version", .content = "content"};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    int32_t ret = AcquireDataSubscribeManager::GetInstance().UploadEventImmediately(event);
    EXPECT_EQ(ret, SUCCESS);
    AcquireDataSubscribeManager::GetInstance().InitEventQueue();
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, PublishEventToSub_FileEventId_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID).WillRepeatedly(Return(true));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "file_client");
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "file_client", obj);
    AcquireDataSubscribeManager::GetInstance().InsertSubscribeRecord(0x01C000007, "file_client");
    SecurityCollector::Event event{.eventId = 0x01C000007, .version = "version", .content = "content",
        .eventSubscribes = {"file_client"}};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &eventCfg) {
            eventCfg.eventType = static_cast<uint32_t>(EventTypeEnum::NORMALE_COLL);
            eventCfg.isSticky = 0;
            return true;
    });
    EXPECT_CALL(*(DataFormat::GetInterface()), CheckRiskContent).WillRepeatedly(Return(true));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillRepeatedly(Return(SUCCESS));
    AcquireDataSubscribeManager::GetInstance().tokenBucket_.store(0);
    bool ret = AcquireDataSubscribeManager::GetInstance().PublishEventToSub(event);
    EXPECT_TRUE(ret);
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "file_client");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, PublishEventToSub_WithFlagAndFileEventId_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID).WillRepeatedly(Return(true));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &eventCfg) {
            eventCfg.eventType = static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL);
            eventCfg.prog = "security_guard";
            return true;
        });
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillRepeatedly(Return(SUCCESS));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "flag_client");
    AcquireDataSubscribeManager::GetInstance().sessionsMap_.clear();
    AcquireDataSubscribeManager::GetInstance().eventToListenner_.clear();
    AcquireDataSubscribeManager::GetInstance().eventFilter_ = nullptr;
    int32_t ret = AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "flag_client", obj);
    EXPECT_EQ(ret, SUCCESS);

    AcquireDataSubscribeManager::GetInstance().sessionsMap_["flag_client"]->subEvents.insert(0x01C000007);
    SecurityCollector::Event event{
        .eventId = 0x01C000007, .version = "version", .content = "content", .eventSubscribes = {"flag_client"}};
    EXPECT_CALL(*(DataFormat::GetInterface()), CheckRiskContent).WillRepeatedly(Return(true));
    AcquireDataSubscribeManager::GetInstance().tokenBucket_.store(1);
    bool result = AcquireDataSubscribeManager::GetInstance().PublishEventToSub(event);
    EXPECT_TRUE(result);
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "flag_client");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, UnSubscribeSc_SecurityGuard_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &eventCfg) {
            eventCfg.eventType = static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL);
            eventCfg.prog = "security_guard";
            return true;
        });
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(),
        UnsubscribeCollectors).WillRepeatedly(Return(SUCCESS));
    auto &mgr = AcquireDataSubscribeManager::GetInstance();
    mgr.eventToListenner_.clear();
    mgr.eventToListenner_[1] = mgr.collectorListener_;
    int32_t ret = mgr.UnSubscribeSc(1);
    EXPECT_EQ(ret, SUCCESS);
    mgr.eventToListenner_.clear();
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, UnSubscribeSc_EventNotFound_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &eventCfg) {
            eventCfg.eventType = static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL);
            eventCfg.prog = "security_guard";
            return true;
        });
    auto &mgr = AcquireDataSubscribeManager::GetInstance();
    mgr.eventToListenner_.clear();
    int32_t ret = mgr.UnSubscribeSc(999);
    EXPECT_EQ(ret, FAILED);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, GetCurrentClientGroup_NotFound_Test, TestSize.Level0)
{
    std::string group = AcquireDataSubscribeManager::GetInstance().GetCurrentClientGroup("not_found_client");
    EXPECT_EQ(group, "");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, GetCurrentClientGroup_NullSession_Test, TestSize.Level0)
{
    AcquireDataSubscribeManager::GetInstance().sessionsMap_["null_session"] = nullptr;
    std::string group = AcquireDataSubscribeManager::GetInstance().GetCurrentClientGroup("null_session");
    EXPECT_EQ(group, "");
    AcquireDataSubscribeManager::GetInstance().sessionsMap_.clear();
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, GetCurrentClientGroup_CollectOnStartZero_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetAllEventIds).WillOnce(Return(std::vector<int64_t>{100}));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &eventCfg) {
            eventCfg.collectOnStart = 0;
            return true;
        });
    AcquireDataSubscribeManager::GetInstance().SubscriberEventOnSgStart();
    EXPECT_TRUE(AcquireDataSubscribeManager::GetInstance().eventToListenner_.empty());
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, SubscriberEventOnSgStart_ListenerNull_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetAllEventIds).WillRepeatedly(Return(std::vector<int64_t>{}));
    auto &mgr = AcquireDataSubscribeManager::GetInstance();
    mgr.collectorListener_ = nullptr;
    mgr.SubscriberEventOnSgStart();
    mgr.collectorListener_ = std::make_shared<AcquireDataSubscribeManager::CollectorListener>();
    EXPECT_TRUE(AcquireDataSubscribeManager::GetInstance().eventToListenner_.empty());
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, InsertSubscribeMute_SubEventNotExist_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "mute_test_client", obj);
    EventMuteFilter filter{};
    filter.eventId = 200;
    int32_t ret = AcquireDataSubscribeManager::GetInstance().InsertSubscribeMute(filter, "mute_test_client");
    EXPECT_EQ(ret, SUCCESS);
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "mute_test_client");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, RemoveSubscribeMute_FilterNotExist_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    AcquireDataSubscribeManager::GetInstance().CreatClient("auditGroup", "filter_not_exist_client", obj);
    EventMuteFilter filter{};
    filter.eventId = 200;
    AcquireDataSubscribeManager::GetInstance().sessionsMap_["filter_not_exist_client"]->subEvents.insert(200);
    int32_t ret = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeMute(filter, "filter_not_exist_client");
    EXPECT_EQ(ret, BAD_PARAM);
    AcquireDataSubscribeManager::GetInstance().DestoryClient("auditGroup", "filter_not_exist_client");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, SubscribeScInSg_ListennerNull_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &eventCfg) {
            eventCfg.eventType = static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL);
            eventCfg.prog = "security_guard";
            return true;
        });
    auto &mgr = AcquireDataSubscribeManager::GetInstance();
    mgr.collectorListener_ = nullptr;
    int32_t ret = mgr.SubscribeScInSg(1000, 0);
    EXPECT_EQ(ret, NULL_OBJECT);
    mgr.collectorListener_ = std::make_shared<AcquireDataSubscribeManager::CollectorListener>();
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, SubscribeSc_GetConfigFail_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(false));
    auto &mgr = AcquireDataSubscribeManager::GetInstance();
    int32_t ret = mgr.SubscribeSc(1001);
    EXPECT_EQ(ret, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, UnSubscribeSc_GetConfigFail_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(false));
    auto &mgr = AcquireDataSubscribeManager::GetInstance();
    int32_t ret = mgr.UnSubscribeSc(1002);
    EXPECT_EQ(ret, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, UnSubscribeSc_SgEventNotFound_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &eventCfg) {
            eventCfg.eventType = static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL);
            eventCfg.prog = "security_guard";
            return true;
        });
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillRepeatedly(Return(SUCCESS));
    auto &mgr = AcquireDataSubscribeManager::GetInstance();
    mgr.SubscribeSc(1003);
    int32_t ret = mgr.UnSubscribeSc(1003);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, UnSubscribeSc_SgUnsubscribeFail_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &eventCfg) {
            eventCfg.eventType = static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL);
            eventCfg.prog = "security_guard";
            return true;
        });
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(),
        UnsubscribeCollectors).WillRepeatedly(Return(FAILED));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    auto &mgr = AcquireDataSubscribeManager::GetInstance();
    mgr.CreatClient("auditGroup", "unsubscribe_fail_client", obj);
    mgr.InsertSubscribeRecord(1004, "unsubscribe_fail_client");
    int32_t ret = mgr.UnSubscribeSc(1004);
    EXPECT_EQ(ret, FAILED);
    mgr.DestoryClient("auditGroup", "unsubscribe_fail_client");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, UnSubscribeSc_ScUnsubscribeFail_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &eventCfg) {
            eventCfg.eventType = static_cast<uint32_t>(EventTypeEnum::SUBSCRIBE_COLL);
            eventCfg.prog = "other_app";
            return true;
        });
    EXPECT_CALL(SecurityCollector::CollectorManager::GetInstance(), Subscribe).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(SecurityCollector::CollectorManager::GetInstance(), Unsubscribe).WillRepeatedly(Return(FAILED));
    auto &mgr = AcquireDataSubscribeManager::GetInstance();
    mgr.SubscribeSc(1005);
    int32_t ret = mgr.UnSubscribeSc(1005);
    EXPECT_EQ(ret, FAILED);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, InsertMute_EventFilterNull_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    auto &mgr = AcquireDataSubscribeManager::GetInstance();
    mgr.eventFilter_ = nullptr;
    EventMuteFilter filter{};
    filter.eventId = 1;
    filter.type = 1;
    filter.isInclude = true;
    int32_t ret = mgr.InsertMute(filter, "mute_filter_null_client");
    EXPECT_EQ(ret, NULL_OBJECT);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, UploadEvent_ContentCheckFail_Test, TestSize.Level0)
{
    SecurityCollector::Event event{.eventId = 1, .version = "version", .content = "content"};
    EXPECT_CALL(*(DataFormat::GetInterface()), CheckRiskContent).WillRepeatedly(Return(false));
    int32_t ret = AcquireDataSubscribeManager::GetInstance().UploadEvent(event);
    EXPECT_EQ(ret, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, UploadEvent_NotBatchUpload_Test, TestSize.Level0)
{
    EXPECT_CALL(*(DataFormat::GetInterface()), CheckRiskContent).WillRepeatedly(Return(true));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &eventCfg) {
            eventCfg.isBatchUpload = 0;
            return true;
        });
    SecurityCollector::Event event{.eventId = 1, .version = "version", .content = "content"};
    int32_t ret = AcquireDataSubscribeManager::GetInstance().UploadEvent(event);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, BatchUploadEvent_FullNotifyEvents_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    AcquireDataSubscribeManager::GetInstance().notifyEvents_.clear();
    for (int i = 0; i < 10; i++) {
        AcquireDataSubscribeManager::GetInstance().notifyEvents_.push_back({});
    }
    SecurityCollector::Event event{.eventId = 1, .version = "version", .content = "content"};
    int32_t ret = AcquireDataSubscribeManager::GetInstance().BatchUploadEvent(event);
    EXPECT_EQ(ret, SUCCESS);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, UploadEventImmediately_TaskCountExceed_Test, TestSize.Level0)
{
    g_crucialTaskCount.store(6000);
    SecurityCollector::Event event{.eventId = 1, .version = "version", .content = "content"};
    int32_t ret = AcquireDataSubscribeManager::GetInstance().UploadEventImmediately(event);
    EXPECT_EQ(ret, SUCCESS);
    g_crucialTaskCount.store(0);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, UploadEventTask_GetConfigFail_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(false));
    SecurityCollector::Event event{.eventId = 1, .version = "version", .content = "content"};
    AcquireDataSubscribeManager::GetInstance().UploadEventTask(event);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, PublishEventToSub_EventCountExceed_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID).WillRepeatedly(Return(true));
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    auto &mgr = AcquireDataSubscribeManager::GetInstance();
    mgr.CreatClient("auditGroup", "publish_client", obj);
    mgr.InsertSubscribeRecord(2000, "publish_client");
    SecurityCollector::Event event{.eventId = 2000, .version = "version", .content = "content"};
    mgr.PublishEventToSub(event);
    mgr.RemoveSubscribeRecord(2000, "publish_client");
    mgr.DestoryClient("auditGroup", "publish_client");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, InsertSubscribeMute_EventFilterFail_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillRepeatedly(Return(SUCCESS));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventGroupConfig).WillRepeatedly(Return(true));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), VerifyAccessToken)
        .WillRepeatedly(Return(AccessToken::PermissionState::PERMISSION_GRANTED));
    EXPECT_CALL(*(AccessToken::AccessTokenKit::GetInterface()), GetTokenType)
        .WillRepeatedly(Return(AccessToken::TypeATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*(AccessToken::TokenIdKit::GetInterface()), IsSystemAppByFullTokenID).WillRepeatedly(Return(true));
    auto &mgr = AcquireDataSubscribeManager::GetInstance();
    sptr<MockRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    mgr.CreatClient("auditGroup", "mute_insert_fail_client", obj);
    mgr.InsertSubscribeRecord(2001, "mute_insert_fail_client");
    EventMuteFilter filter{};
    filter.eventId = 2001;
    filter.type = 1;
    filter.isInclude = true;
    int32_t ret = mgr.InsertSubscribeMute(filter, "mute_insert_fail_client");
    EXPECT_EQ(ret, NULL_OBJECT);
    mgr.RemoveSubscribeRecord(2001, "mute_insert_fail_client");
    mgr.DestoryClient("auditGroup", "mute_insert_fail_client");
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, RemoveSubscribeRecord_ClientNotFound_Test, TestSize.Level0)
{
    int32_t ret = AcquireDataSubscribeManager::GetInstance().RemoveSubscribeRecord(999, "mute_insert_fail_client");
    EXPECT_EQ(ret, BAD_PARAM);
}

HWTEST_F(SecurityGuardDataCollectSaNewTest, SubscriberEventOnSgStart_SubscribeFail_Test, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetAllEventIds).WillRepeatedly(Return(std::vector<int64_t>{100}));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetEventConfig)
        .WillRepeatedly([](int64_t eventId, EventCfg &eventCfg) {
            eventCfg.collectOnStart = 1;
            return true;
        });
    EXPECT_CALL(SecurityCollector::DataCollection::GetInstance(), SubscribeCollectors).WillOnce(Return(SUCCESS));
    AcquireDataSubscribeManager::GetInstance().SubscriberEventOnSgStart();
    EXPECT_FALSE(AcquireDataSubscribeManager::GetInstance().eventToListenner_.empty());
}
}
