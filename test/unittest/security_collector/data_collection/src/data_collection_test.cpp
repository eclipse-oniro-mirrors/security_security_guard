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
#include <memory>
#include "gmock/gmock.h"
#define private public
#include "data_collection.h"
#include "security_event_ruler.h"
#include "collector_cfg_marshalling.h"
#undef private
using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityCollector;
namespace OHOS::Security::SecurityCollectorTest {
class DataCollectionTest : public testing::Test {
public:
    static void SetUpTestCase() {};

    static void TearDownTestCase() {};

    void SetUp() override {};

    void TearDown() override {};
};

class TestFwk : public SecurityCollector::ICollectorFwk {
public:
    void OnNotify(const Event &event) override {};
    std::string GetExtraInfo() override { return "";};
};

class TestCollector : public SecurityCollector::ICollector {
public:
    int Start(std::shared_ptr<ICollectorFwk> api) override {return 0;};
    int Stop()  override {return 0;};
};

class MockMyClass : public DataCollection {
public:
    MOCK_METHOD3(LoadCollector, int(
        int64_t eventId, std::string path, std::shared_ptr<ICollectorFwk> api));
    MOCK_METHOD2(GetCollectorPath, ErrorCode(int64_t eventId, std::string &path));
    MOCK_METHOD1(IsCollectorStarted, bool(int64_t eventId));
};

HWTEST_F(DataCollectionTest, Instance01, testing::ext::TestSize.Level0)
{
    int32_t type = 0;
    EXPECT_TRUE(DataCollection::GetInstance().GetCollectorType(0, type) != SUCCESS);
}

HWTEST_F(DataCollectionTest, Instance02, testing::ext::TestSize.Level0)
{
    std::shared_ptr<ICollectorFwk> api = std::make_shared<TestFwk> ();
    EXPECT_EQ(DataCollection::GetInstance().LoadCollector(1, "", api), FAILED);
    std::vector<SecurityEvent> eventIds {};
    SecurityEventRuler ruler;
    EXPECT_EQ(DataCollection::GetInstance().LoadCollector("", ruler, eventIds), FAILED);
}

HWTEST_F(DataCollectionTest, StartCollectors01, testing::ext::TestSize.Level0)
{
    DataCollection collec {};
    std::vector<int64_t> eventIds {};
    std::shared_ptr<SecurityCollector::ICollectorFwk> api;
    EXPECT_FALSE(collec.StartCollectors(eventIds, api));
    eventIds.emplace_back(1);
    EXPECT_FALSE(collec.StartCollectors(eventIds, api));
}

HWTEST_F(DataCollectionTest, StartCollectors02, testing::ext::TestSize.Level0)
{
    DataCollection collec {};
    std::vector<int64_t> eventIds {1};
    std::shared_ptr<SecurityCollector::ICollectorFwk> api = std::make_shared<TestFwk> ();
    EXPECT_FALSE(collec.StartCollectors(eventIds, api));
}

HWTEST_F(DataCollectionTest, StartCollectors03, testing::ext::TestSize.Level0)
{
    MockMyClass myOb;
    std::vector<int64_t> eventIds {1};
    std::shared_ptr<SecurityCollector::ICollectorFwk> api = std::make_shared<TestFwk> ();
    EXPECT_CALL(myOb, IsCollectorStarted).WillOnce(Return(false));
    EXPECT_CALL(myOb, GetCollectorPath).WillOnce(Return(SUCCESS));
    EXPECT_CALL(myOb, LoadCollector(1, "", api)).WillOnce(Return(SUCCESS));
    EXPECT_TRUE(myOb.StartCollectors(eventIds, api));
}

HWTEST_F(DataCollectionTest, StartCollectors04, testing::ext::TestSize.Level0)
{
    MockMyClass myOb;
    std::vector<int64_t> eventIds {1};
    std::shared_ptr<SecurityCollector::ICollectorFwk> api = std::make_shared<TestFwk> ();
    EXPECT_CALL(myOb, IsCollectorStarted).WillOnce(Return(false));
    EXPECT_CALL(myOb, GetCollectorPath).WillOnce(Return(SUCCESS));
    EXPECT_CALL(myOb, LoadCollector(1, "", api)).WillOnce(Return(FAILED));
    EXPECT_FALSE(myOb.StartCollectors(eventIds, api));
}

HWTEST_F(DataCollectionTest, StartCollectors05, testing::ext::TestSize.Level0)
{
    MockMyClass myOb;
    std::vector<int64_t> eventIds {1};
    std::shared_ptr<SecurityCollector::ICollectorFwk> api = std::make_shared<TestFwk> ();
    EXPECT_CALL(myOb, GetCollectorPath).WillOnce(Return(FAILED));
    EXPECT_CALL(myOb, IsCollectorStarted).WillOnce(Return(false));
    EXPECT_FALSE(myOb.StartCollectors(eventIds, api));
}

HWTEST_F(DataCollectionTest, StartCollectors06, testing::ext::TestSize.Level0)
{
    MockMyClass myOb;
    std::vector<int64_t> eventIds {1};
    std::shared_ptr<SecurityCollector::ICollectorFwk> api = std::make_shared<TestFwk> ();
    EXPECT_CALL(myOb, IsCollectorStarted).WillOnce(Return(true));
    EXPECT_TRUE(myOb.StartCollectors(eventIds, api));
}

HWTEST_F(DataCollectionTest, StopCollectors01, testing::ext::TestSize.Level0)
{
    DataCollection myOb;
    std::vector<int64_t> eventIds;
    EXPECT_TRUE(myOb.StopCollectors(eventIds));
}

HWTEST_F(DataCollectionTest, StopCollectors02, testing::ext::TestSize.Level0)
{
    DataCollection myOb;
    std::vector<int64_t> eventIds {1};
    EXPECT_TRUE(myOb.StopCollectors(eventIds));
}

HWTEST_F(DataCollectionTest, StopCollectors03, testing::ext::TestSize.Level0)
{
    DataCollection myOb;
    std::vector<int64_t> eventIds {1};
    EXPECT_TRUE(myOb.StopCollectors(eventIds));
}

HWTEST_F(DataCollectionTest, StopCollectors04, testing::ext::TestSize.Level0)
{
    DataCollection myOb;
    myOb.eventIdToLoaderMap_.emplace(1, LibLoader("testPath"));
    std::vector<int64_t> eventIds {1};
    EXPECT_FALSE(myOb.StopCollectors(eventIds));
}

class MockMyCheckFileStreamClass : public DataCollection {
public:
    MOCK_METHOD1(CheckFileStream, ErrorCode(std::ifstream &stream));
};

HWTEST_F(DataCollectionTest, GetCollectorPath01, testing::ext::TestSize.Level0)
{
    MockMyCheckFileStreamClass myOb;
    std::string path;
    EXPECT_CALL(myOb, CheckFileStream).WillOnce(Return(FAILED));
    EXPECT_EQ(myOb.GetCollectorPath(1, path), FAILED);
}

HWTEST_F(DataCollectionTest, GetCollectorPath02, testing::ext::TestSize.Level0)
{
    MockMyCheckFileStreamClass myOb;
    std::string path;
    EXPECT_CALL(myOb, CheckFileStream).WillOnce(Return(SUCCESS));
    EXPECT_EQ(myOb.GetCollectorPath(0, path), FAILED);
}

HWTEST_F(DataCollectionTest, GetCollectorType01, testing::ext::TestSize.Level0)
{
    MockMyCheckFileStreamClass myOb;
    int32_t collectorType;
    EXPECT_CALL(myOb, CheckFileStream).WillOnce(Return(FAILED));
    EXPECT_EQ(myOb.GetCollectorType(1, collectorType), FAILED);
}

HWTEST_F(DataCollectionTest, GetCollectorType02, testing::ext::TestSize.Level0)
{
    MockMyCheckFileStreamClass myOb;
    int32_t collectorType;
    EXPECT_CALL(myOb, CheckFileStream).WillOnce(Return(SUCCESS));
    EXPECT_EQ(myOb.GetCollectorType(0, collectorType), FAILED);
}

class MockQuerySecurityEventClass : public DataCollection {
public:
    MOCK_METHOD3(LoadCollector, ErrorCode(std::string path, const SecurityEventRuler &ruler,
        std::vector<SecurityEvent> &events));
    MOCK_METHOD2(GetCollectorPath, ErrorCode(int64_t eventId, std::string& path));
};

HWTEST_F(DataCollectionTest, SecurityGuardSubscribeCollector01, testing::ext::TestSize.Level0)
{
    std::vector<int64_t> eventIds;
    MockMyClass myOb;
    EXPECT_TRUE(myOb.SecurityGuardSubscribeCollector(eventIds));
}

HWTEST_F(DataCollectionTest, SecurityGuardSubscribeCollector04, testing::ext::TestSize.Level0)
{
    std::vector<int64_t> eventIds {1};
    MockMyClass myOb;
    std::shared_ptr<SecurityCollector::ICollectorFwk> api;
    EXPECT_CALL(myOb, GetCollectorPath).WillOnce(Return(SUCCESS));
    EXPECT_CALL(myOb, LoadCollector(1, "", api)).WillOnce(Return(SUCCESS));
    EXPECT_CALL(myOb, IsCollectorStarted).WillOnce(Return(false));
    EXPECT_TRUE(myOb.SecurityGuardSubscribeCollector(eventIds));
}

HWTEST_F(DataCollectionTest, SecurityGuardSubscribeCollector02, testing::ext::TestSize.Level0)
{
    std::vector<int64_t> eventIds {1};
    MockMyClass myOb;
    std::shared_ptr<SecurityCollector::ICollectorFwk> api;
    EXPECT_CALL(myOb, GetCollectorPath).WillOnce(Return(SUCCESS));
    EXPECT_CALL(myOb, LoadCollector(1, "", api)).WillOnce(Return(FAILED));
    EXPECT_CALL(myOb, IsCollectorStarted).WillOnce(Return(false));
    EXPECT_TRUE(myOb.SecurityGuardSubscribeCollector(eventIds));
}

HWTEST_F(DataCollectionTest, SecurityGuardSubscribeCollector03, testing::ext::TestSize.Level0)
{
    std::vector<int64_t> eventIds {1};
    MockMyClass myOb;
    EXPECT_CALL(myOb, GetCollectorPath).WillOnce(Return(FAILED));
    EXPECT_CALL(myOb, IsCollectorStarted).WillOnce(Return(false));
    EXPECT_TRUE(myOb.SecurityGuardSubscribeCollector(eventIds));
}

HWTEST_F(DataCollectionTest, SecurityGuardSubscribeCollector05, testing::ext::TestSize.Level0)
{
    std::vector<int64_t> eventIds {1};
    MockMyClass myOb;
    std::shared_ptr<SecurityCollector::ICollectorFwk> api = std::make_shared<TestFwk> ();
    EXPECT_CALL(myOb, IsCollectorStarted).WillOnce(Return(true));
    EXPECT_TRUE(myOb.SecurityGuardSubscribeCollector(eventIds));
}

HWTEST_F(DataCollectionTest, SecurityGuardSubscribeCollector06, testing::ext::TestSize.Level0)
{
    MockQuerySecurityEventClass myOb;
    std::vector<SecurityEvent> events;
    std::vector<SecurityEventRuler> rulers;
    EXPECT_EQ(myOb.QuerySecurityEvent(rulers, events), FAILED);

    SecurityEventRuler rule(11111);
    std::string path("/system/lib64/chipset-pub-sdk/libeventhandler.z.so");
    rulers.emplace_back(rule);
    EXPECT_CALL(myOb, GetCollectorPath).WillOnce(Return(SUCCESS));
    EXPECT_CALL(myOb, LoadCollector).WillOnce(Return(SUCCESS));
    EXPECT_EQ(myOb.QuerySecurityEvent(rulers, events), SUCCESS);
}

HWTEST_F(DataCollectionTest, SecurityGuardSubscribeCollector07, testing::ext::TestSize.Level0)
{
    MockQuerySecurityEventClass myOb;
    std::vector<SecurityEvent> events;
    std::vector<SecurityEventRuler> rulers;
    EXPECT_EQ(myOb.QuerySecurityEvent(rulers, events), FAILED);

    SecurityEventRuler rule(11111);
    std::string path("/system/lib64/chipset-pub-sdk/libeventhandler.z.so");
    rulers.emplace_back(rule);
    EXPECT_CALL(myOb, GetCollectorPath).WillOnce(Return(FAILED));

    EXPECT_EQ(myOb.QuerySecurityEvent(rulers, events), FAILED);
}

HWTEST_F(DataCollectionTest, SecurityGuardSubscribeCollector08, testing::ext::TestSize.Level0)
{
    MockQuerySecurityEventClass myOb;
    std::vector<SecurityEvent> events;
    std::vector<SecurityEventRuler> rulers;
    EXPECT_EQ(myOb.QuerySecurityEvent(rulers, events), FAILED);

    SecurityEventRuler rule(11111);
    std::string path("/system/lib64/chipset-pub-sdk/libeventhandler.z.so");
    rulers.emplace_back(rule);

    EXPECT_CALL(myOb, GetCollectorPath).WillOnce(Return(SUCCESS));
    EXPECT_CALL(myOb, LoadCollector).WillOnce(Return(FAILED));
    EXPECT_EQ(myOb.QuerySecurityEvent(rulers, events), FAILED);
}

HWTEST_F(DataCollectionTest, LoadCollectorWithApi01, testing::ext::TestSize.Level0)
{
    std::string path = "/system/lib64/module/security/libsecurityguard_napi.z.so";
    std::shared_ptr<ICollectorFwk> api = nullptr;
    int64_t eventId = 1;
    EXPECT_EQ(DataCollection::GetInstance().LoadCollector(eventId, path, api), FAILED);
}

HWTEST_F(DataCollectionTest, LoadCollectorWithNonApi01, testing::ext::TestSize.Level0)
{
    std::string path = "/system/lib64/module/security/libsecurityguard_napi.z.so";
    std::vector<SecurityEvent> events;
    SecurityCollector::SecurityEventRuler ruler(11111);
    EXPECT_EQ(DataCollection::GetInstance().LoadCollector(path, ruler, events), FAILED);
}

HWTEST_F(DataCollectionTest, ICollector01, testing::ext::TestSize.Level1)
{
    TestCollector collector;
    std::vector<SecurityEvent> eventIds {};
    SecurityEventRuler ruler;
    std::shared_ptr<ICollectorFwk> api = std::make_shared<TestFwk> ();
    EXPECT_EQ(collector.IsStartWithSub(), 0);
    EXPECT_EQ(collector.Query(ruler, eventIds), 0);
    EXPECT_EQ(collector.Subscribe(api, 0), 0);
    EXPECT_EQ(collector.Unsubscribe(0), 0);
}

HWTEST_F(DataCollectionTest, SubscribeCollectors01, testing::ext::TestSize.Level0)
{
    DataCollection collec {};
    std::vector<int64_t> eventIds {};
    std::shared_ptr<SecurityCollector::ICollectorFwk> api;
    EXPECT_NE(collec.SubscribeCollectors(eventIds, api), SUCCESS);
    eventIds.emplace_back(1);
    EXPECT_NE(collec.SubscribeCollectors(eventIds, api), SUCCESS);
}

HWTEST_F(DataCollectionTest, SubscribeCollectors02, testing::ext::TestSize.Level0)
{
    DataCollection collec {};
    std::vector<int64_t> eventIds {1};
    std::shared_ptr<SecurityCollector::ICollectorFwk> api = std::make_shared<TestFwk> ();
    EXPECT_NE(collec.SubscribeCollectors(eventIds, api), SUCCESS);
}

HWTEST_F(DataCollectionTest, SubscribeCollectors03, testing::ext::TestSize.Level0)
{
    MockMyClass myOb;
    std::vector<int64_t> eventIds {1};
    std::shared_ptr<SecurityCollector::ICollectorFwk> api = std::make_shared<TestFwk> ();
    EXPECT_CALL(myOb, IsCollectorStarted).WillOnce(Return(false));
    EXPECT_CALL(myOb, GetCollectorPath).WillOnce(Return(SUCCESS));
    EXPECT_CALL(myOb, LoadCollector(1, "", api)).WillOnce(Return(SUCCESS));
    EXPECT_EQ(myOb.SubscribeCollectors(eventIds, api), SUCCESS);
}

HWTEST_F(DataCollectionTest, SubscribeCollectors04, testing::ext::TestSize.Level0)
{
    MockMyClass myOb;
    std::vector<int64_t> eventIds {1};
    std::shared_ptr<SecurityCollector::ICollectorFwk> api = std::make_shared<TestFwk> ();
    EXPECT_CALL(myOb, IsCollectorStarted).WillOnce(Return(false));
    EXPECT_CALL(myOb, GetCollectorPath).WillOnce(Return(SUCCESS));
    EXPECT_CALL(myOb, LoadCollector(1, "", api)).WillOnce(Return(FAILED));
    EXPECT_NE(myOb.SubscribeCollectors(eventIds, api), SUCCESS);
}

HWTEST_F(DataCollectionTest, SubscribeCollectors05, testing::ext::TestSize.Level0)
{
    MockMyClass myOb;
    std::vector<int64_t> eventIds {1};
    std::shared_ptr<SecurityCollector::ICollectorFwk> api = std::make_shared<TestFwk> ();
    EXPECT_CALL(myOb, GetCollectorPath).WillOnce(Return(FAILED));
    EXPECT_CALL(myOb, IsCollectorStarted).WillOnce(Return(false));
    EXPECT_NE(myOb.SubscribeCollectors(eventIds, api), SUCCESS);
}

HWTEST_F(DataCollectionTest, SubscribeCollectors06, testing::ext::TestSize.Level0)
{
    MockMyClass myOb;
    std::vector<int64_t> eventIds {1};
    std::shared_ptr<SecurityCollector::ICollectorFwk> api = std::make_shared<TestFwk> ();
    EXPECT_CALL(myOb, IsCollectorStarted).WillOnce(Return(true));
    EXPECT_EQ(myOb.SubscribeCollectors(eventIds, api), SUCCESS);
}

HWTEST_F(DataCollectionTest, UnsubscribeCollectors01, testing::ext::TestSize.Level0)
{
    DataCollection myOb;
    std::vector<int64_t> eventIds;
    EXPECT_EQ(myOb.UnsubscribeCollectors(eventIds), SUCCESS);
}

HWTEST_F(DataCollectionTest, UnsubscribeCollectors02, testing::ext::TestSize.Level0)
{
    DataCollection myOb;
    std::vector<int64_t> eventIds {1};
    EXPECT_EQ(myOb.UnsubscribeCollectors(eventIds), SUCCESS);
}

HWTEST_F(DataCollectionTest, UnsubscribeCollectors03, testing::ext::TestSize.Level0)
{
    DataCollection myOb;
    std::vector<int64_t> eventIds {1};
    EXPECT_EQ(myOb.UnsubscribeCollectors(eventIds), SUCCESS);
}

HWTEST_F(DataCollectionTest, UnsubscribeCollectors04, testing::ext::TestSize.Level0)
{
    DataCollection myOb;
    myOb.eventIdToLoaderMap_.emplace(1, LibLoader("testPath"));
    std::vector<int64_t> eventIds {1};
    EXPECT_NE(myOb.UnsubscribeCollectors(eventIds), SUCCESS);
}

HWTEST_F(DataCollectionTest, SubscribeCollectorsBySticky01, testing::ext::TestSize.Level0)
{
    DataCollection collec {};
    std::vector<int64_t> eventIds {};
    std::shared_ptr<SecurityCollector::ICollectorFwk> api;
    EXPECT_NE(collec.SubscribeCollectorsBySticky(eventIds, api), SUCCESS);
    eventIds.emplace_back(1);
    EXPECT_NE(collec.SubscribeCollectorsBySticky(eventIds, api), SUCCESS);
}

HWTEST_F(DataCollectionTest, SubscribeCollectorsBySticky02, testing::ext::TestSize.Level0)
{
    DataCollection collec {};
    std::vector<int64_t> eventIds {1};
    std::shared_ptr<SecurityCollector::ICollectorFwk> api = std::make_shared<TestFwk> ();
    EXPECT_NE(collec.SubscribeCollectorsBySticky(eventIds, api), SUCCESS);
}

HWTEST_F(DataCollectionTest, SubscribeCollectorsBySticky03, testing::ext::TestSize.Level0)
{
    MockMyClass myOb;
    std::vector<int64_t> eventIds {1};
    std::shared_ptr<SecurityCollector::ICollectorFwk> api = std::make_shared<TestFwk> ();
    EXPECT_CALL(myOb, IsCollectorStarted).WillOnce(Return(false));
    EXPECT_CALL(myOb, GetCollectorPath).WillOnce(Return(SUCCESS));
    EXPECT_CALL(myOb, LoadCollector(1, "", api)).WillOnce(Return(SUCCESS));
    EXPECT_EQ(myOb.SubscribeCollectorsBySticky(eventIds, api), SUCCESS);
}

HWTEST_F(DataCollectionTest, SubscribeCollectorsBySticky04, testing::ext::TestSize.Level0)
{
    MockMyClass myOb;
    std::vector<int64_t> eventIds {1};
    std::shared_ptr<SecurityCollector::ICollectorFwk> api = std::make_shared<TestFwk> ();
    EXPECT_CALL(myOb, IsCollectorStarted).WillOnce(Return(false));
    EXPECT_CALL(myOb, GetCollectorPath).WillOnce(Return(SUCCESS));
    EXPECT_CALL(myOb, LoadCollector(1, "", api)).WillOnce(Return(FAILED));
    EXPECT_NE(myOb.SubscribeCollectorsBySticky(eventIds, api), SUCCESS);
}

HWTEST_F(DataCollectionTest, SubscribeCollectorsBySticky05, testing::ext::TestSize.Level0)
{
    MockMyClass myOb;
    std::vector<int64_t> eventIds {1};
    std::shared_ptr<SecurityCollector::ICollectorFwk> api = std::make_shared<TestFwk> ();
    EXPECT_CALL(myOb, GetCollectorPath).WillOnce(Return(FAILED));
    EXPECT_CALL(myOb, IsCollectorStarted).WillOnce(Return(false));
    EXPECT_NE(myOb.SubscribeCollectorsBySticky(eventIds, api), SUCCESS);
}
}