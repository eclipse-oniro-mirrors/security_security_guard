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
#include <atomic>
#include <thread>
#include <unistd.h>
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

class MockBatchQueryClass : public DataCollection {
public:
    MOCK_METHOD4(LoadAndQueryBySoPath, int(const std::string &soPath, const std::vector<SecurityEventRuler> &rulers,
        std::vector<SecurityEvent> &events, std::vector<int64_t> &failedEventIds));
    MOCK_METHOD2(GetCollectorPath, ErrorCode(int64_t eventId, std::string& path));
};

HWTEST_F(DataCollectionTest, QuerySecurityEventBatch01, testing::ext::TestSize.Level0)
{
    MockBatchQueryClass myOb;
    std::vector<SecurityEventRuler> rulers;
    std::vector<SecurityEvent> events;
    std::vector<int64_t> failedEventIds;
    EXPECT_EQ(myOb.QuerySecurityEventBatch(rulers, events, failedEventIds), FAILED);
}

HWTEST_F(DataCollectionTest, QuerySecurityEventBatch02, testing::ext::TestSize.Level0)
{
    MockBatchQueryClass myOb;
    SecurityEventRuler rule(11111);
    std::vector<SecurityEventRuler> rulers;
    rulers.emplace_back(rule);
    std::vector<SecurityEvent> events;
    std::vector<int64_t> failedEventIds;
    EXPECT_CALL(myOb, GetCollectorPath).WillOnce(Return(FAILED));
    EXPECT_EQ(myOb.QuerySecurityEventBatch(rulers, events, failedEventIds), SUCCESS);
    EXPECT_EQ(failedEventIds.size(), 1UL);
}

HWTEST_F(DataCollectionTest, QuerySecurityEventBatch03, testing::ext::TestSize.Level0)
{
    MockBatchQueryClass myOb;
    SecurityEventRuler rule(11111);
    std::vector<SecurityEventRuler> rulers;
    rulers.emplace_back(rule);
    std::vector<SecurityEvent> events;
    std::vector<int64_t> failedEventIds;
    EXPECT_CALL(myOb, GetCollectorPath).WillOnce(Return(SUCCESS));
    EXPECT_CALL(myOb, LoadAndQueryBySoPath).WillOnce(Return(SUCCESS));
    EXPECT_EQ(myOb.QuerySecurityEventBatch(rulers, events, failedEventIds), SUCCESS);
}

HWTEST_F(DataCollectionTest, QuerySecurityEventBatch04, testing::ext::TestSize.Level0)
{
    MockBatchQueryClass myOb;
    SecurityEventRuler rule1(11111);
    SecurityEventRuler rule2(22222);
    std::vector<SecurityEventRuler> rulers;
    rulers.emplace_back(rule1);
    rulers.emplace_back(rule2);
    std::vector<SecurityEvent> events;
    std::vector<int64_t> failedEventIds;
    EXPECT_CALL(myOb, GetCollectorPath)
        .WillOnce(Return(SUCCESS))
        .WillOnce(Return(FAILED));
    EXPECT_CALL(myOb, LoadAndQueryBySoPath).WillOnce(Return(FAILED));
    EXPECT_EQ(myOb.QuerySecurityEventBatch(rulers, events, failedEventIds), SUCCESS);
}

HWTEST_F(DataCollectionTest, QuerySecurityEventBatch05, testing::ext::TestSize.Level0)
{
    MockBatchQueryClass myOb;
    SecurityEventRuler rule1(11111);
    SecurityEventRuler rule2(22222);
    std::vector<SecurityEventRuler> rulers;
    rulers.emplace_back(rule1);
    rulers.emplace_back(rule2);
    std::vector<SecurityEvent> events;
    std::vector<int64_t> failedEventIds;
    EXPECT_CALL(myOb, GetCollectorPath)
        .WillOnce(Return(FAILED))
        .WillOnce(Return(FAILED));
    EXPECT_EQ(myOb.QuerySecurityEventBatch(rulers, events, failedEventIds), SUCCESS);
    EXPECT_EQ(failedEventIds.size(), 2UL);
}

HWTEST_F(DataCollectionTest, QuerySecurityEventBatch06, testing::ext::TestSize.Level0)
{
    MockBatchQueryClass myOb;
    SecurityEventRuler rule(11111);
    std::vector<SecurityEventRuler> rulers;
    rulers.emplace_back(rule);
    std::vector<SecurityEvent> events;
    std::vector<int64_t> failedEventIds;
    EXPECT_CALL(myOb, GetCollectorPath).WillOnce(Return(SUCCESS));
    EXPECT_CALL(myOb, LoadAndQueryBySoPath).WillOnce([](const std::string &soPath,
        const std::vector<SecurityEventRuler> &rulers,
        std::vector<SecurityEvent> &events, std::vector<int64_t> &failedEventIds) {
            for (const auto &r : rulers) {
                failedEventIds.push_back(r.GetEventId());
            }
            return FAILED;
        });
    EXPECT_EQ(myOb.QuerySecurityEventBatch(rulers, events, failedEventIds), SUCCESS);
    EXPECT_EQ(failedEventIds.size(), 1UL);
}

HWTEST_F(DataCollectionTest, ICollectorBatchQuery01, testing::ext::TestSize.Level0)
{
    TestCollector collector;
    std::vector<SecurityEvent> events;
    std::vector<int64_t> failedEventIds;
    SecurityEventRuler ruler1(11111);
    SecurityEventRuler ruler2(22222);
    std::vector<SecurityEventRuler> rulers;
    rulers.emplace_back(ruler1);
    rulers.emplace_back(ruler2);
    EXPECT_EQ(collector.BatchQuery(rulers, events, failedEventIds), 0);
}

HWTEST_F(DataCollectionTest, ICollectorBatchQuery02, testing::ext::TestSize.Level0)
{
    TestCollector collector;
    std::vector<SecurityEvent> events;
    std::vector<int64_t> failedEventIds;
    std::vector<SecurityEventRuler> rulers;
    EXPECT_EQ(collector.BatchQuery(rulers, events, failedEventIds), 0);
}

HWTEST_F(DataCollectionTest, ICollectorBatchQuery03, testing::ext::TestSize.Level0)
{
    class MixexCollector : public SecurityCollector::ICollector {
    public:
        int queryCallCount_ = 0;
        int Start(std::shared_ptr<ICollectorFwk> api) override { return 0; };
        int Stop() override { return 0; };
        int Query(const SecurityEventRuler &ruler, std::vector<SecurityEvent> &events) override {
            queryCallCount_++;
            if (queryCallCount_ == 1) {
                events.emplace_back(SecurityEvent(11111, "v1", "content1"));
                return 0;
            }
            return -1;
        };
    };
    MixexCollector collector;
    std::vector<SecurityEvent> events;
    std::vector<int64_t> failedEventIds;
    SecurityEventRuler ruler1(11111);
    SecurityEventRuler ruler2(22222);
    std::vector<SecurityEventRuler> rulers;
    rulers.emplace_back(ruler1);
    rulers.emplace_back(ruler2);
    EXPECT_EQ(collector.BatchQuery(rulers, events, failedEventIds), 0);
    EXPECT_EQ(events.size(), 1UL);
    EXPECT_EQ(failedEventIds.size(), 1UL);
}

// 覆盖 opMutex_ 串行化契约：查询（dlopen/登记/dlsym）与 CloseLib（dlclose）并发互斥，
// 查询线程不会在执行期间被卸载其 .so（use-after-close 回归防护）。
// 用非 gmock 覆写取路径（gmock 期望非线程安全），指向真实系统 so（无 GetCollector 导出，
// 查询将失败于 dlsym，仍完整经过 dlopen -> needCloseLibMap_ 登记 -> CallGetCollector 竞争面）。
// ARM32 板子无 /system/lib64，按 lib64/lib 顺序探测；两者皆缺失则跳过（dlopen 竞争面不可构造）。
static std::string SelectSystemHilogSo()
{
    const std::vector<std::string> candidates = {
        "/system/lib64/libhilog.z.so",
        "/system/lib/libhilog.z.so",
    };
    for (const auto &path : candidates) {
        if (access(path.c_str(), F_OK) == 0) {
            return path;
        }
    }
    return "";
}

class ConcurrentQueryCollection : public DataCollection {
public:
    ErrorCode GetCollectorPath(int64_t eventId, std::string &path) override
    {
        path = realSoPath;
        return SUCCESS;
    }

    std::string realSoPath;
};

HWTEST_F(DataCollectionTest, QuerySecurityEventConcurrentWithCloseLib001, TestSize.Level1)
{
    const std::string soPath = SelectSystemHilogSo();
    if (soPath.empty()) {
        GTEST_LOG_(WARNING) << "libhilog.z.so not present in /system/lib{,64}, skip";
        return;
    }
    ConcurrentQueryCollection collection;
    collection.realSoPath = soPath;
    std::vector<SecurityEventRuler> rulers;
    rulers.emplace_back(SecurityEventRuler(11111));
    constexpr int loop = 200;
    std::atomic<int> failedCount {0};
    auto queryTask = [&collection, &rulers, &failedCount]() {
        for (int i = 0; i < loop; i++) {
            std::vector<SecurityEvent> events;
            if (collection.QuerySecurityEvent(rulers, events) != SUCCESS) {
                failedCount.fetch_add(1);
            }
        }
    };
    auto closeTask = [&collection]() {
        for (int i = 0; i < loop; i++) {
            collection.CloseLib();
        }
    };
    std::thread queryThread1(queryTask);
    std::thread queryThread2(queryTask);
    std::thread closeThread(closeTask);
    queryThread1.join();
    queryThread2.join();
    closeThread.join();
    // 全部查询按预期 FAILED（so 无 GetCollector 导出），且全程无崩溃
    EXPECT_EQ(failedCount.load(), 2 * loop);
}

HWTEST_F(DataCollectionTest, QuerySecurityEventBatchConcurrentWithCloseLib001, TestSize.Level1)
{
    const std::string soPath = SelectSystemHilogSo();
    if (soPath.empty()) {
        GTEST_LOG_(WARNING) << "libhilog.z.so not present in /system/lib{,64}, skip";
        return;
    }
    ConcurrentQueryCollection collection;
    collection.realSoPath = soPath;
    std::vector<SecurityEventRuler> rulers;
    rulers.emplace_back(SecurityEventRuler(11111));
    constexpr int loop = 200;
    std::atomic<int> failedIdsCount {0};
    auto queryTask = [&collection, &rulers, &failedIdsCount]() {
        for (int i = 0; i < loop; i++) {
            std::vector<SecurityEvent> events;
            std::vector<int64_t> failedEventIds;
            (void)collection.QuerySecurityEventBatch(rulers, events, failedEventIds);
            failedIdsCount.fetch_add(static_cast<int>(failedEventIds.size()));
        }
    };
    auto closeTask = [&collection]() {
        for (int i = 0; i < loop; i++) {
            collection.CloseLib();
        }
    };
    std::thread queryThread1(queryTask);
    std::thread queryThread2(queryTask);
    std::thread closeThread(closeTask);
    queryThread1.join();
    queryThread2.join();
    closeThread.join();
    // 每个 ruler 每次都失败登记（so 无 GetCollector 导出），且全程无崩溃
    EXPECT_EQ(failedIdsCount.load(), 2 * loop);
}
}