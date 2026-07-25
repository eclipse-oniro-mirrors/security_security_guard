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

#include "collector_interface_test.h"
#define private public
#include "event_define.h"
#include "security_collector_subscribe_info.h"
#include "security_collector_run_manager.h"
#include "i_collector_subscriber.h"
#include "security_collector_define.h"
#include "collector_manager.h"
#include "security_guard_define.h"
#include "security_event_ruler.h"
#undef private

namespace OHOS::Security::SecurityCollector {

int32_t CollectorSubscriberTestImpl::OnNotify(const Event &event)
{
    return 0;
}

void CollectorFwkTestImpl::OnNotify(const Event &event)
{
}
}

namespace OHOS::Security::SecurityGuardTest {
class SecurityCollectorSubscriber : public SecurityCollector::ICollectorSubscriber {
public:
    explicit SecurityCollectorSubscriber(
        const SecurityCollector::Event &event) : SecurityCollector::ICollectorSubscriber(event) {};
    ~SecurityCollectorSubscriber() override = default;
    int32_t OnNotify(const SecurityCollector::Event &event) override
    {
        return 0;
    };
};

void CollectorInterfaceTest::SetUpTestCase()
{
}

void CollectorInterfaceTest::TearDownTestCase()
{
}

void CollectorInterfaceTest::SetUp()
{
}

void CollectorInterfaceTest::TearDown()
{
}

/**
 * @tc.name: GetExtraInfo001
 * @tc.desc: ICollectorFwk GetExtraInfo
 * @tc.type: FUNC
 * @tc.require: AR20240110334295
 */
HWTEST_F(CollectorInterfaceTest, GetExtraInfo001, testing::ext::TestSize.Level1)
{
    int64_t eventId = 1;
    std::string version = "version";
    std::string content = "content";
    std::string extra = "extra";
    SecurityCollector::Event event = {eventId, version, content, extra};
    int64_t duration = 2;
    const SecurityCollector::SecurityCollectorSubscribeInfo subscriberInfo{event, duration, true};
    std::shared_ptr<SecurityCollector::SecurityCollectorSubscriber> subscriber =
        std::make_shared<SecurityCollector::SecurityCollectorSubscriber>("appName", subscriberInfo, nullptr, nullptr);
    SecurityCollector::SecurityCollectorRunManager::CollectorListenner listener =
        SecurityCollector::SecurityCollectorRunManager::CollectorListenner(subscriber);
    std::string result = listener.GetExtraInfo();
    EXPECT_EQ(result, extra);
    EXPECT_EQ(listener.GetEventId(), 0);
    SecurityCollector::CollectorFwkTestImpl impl =
        SecurityCollector::CollectorFwkTestImpl(subscriber);
    result = impl.GetExtraInfo();
    std::string extra1 = std::string();
    EXPECT_EQ(result, extra1);
}

/**
 * @tc.name: QuerySecurityEvent001
 * @tc.desc: CollectorManager QuerySecurityEvent
 * @tc.type: FUNC
 * @tc.require: AR20240110334295
 */
HWTEST_F(CollectorInterfaceTest, QuerySecurityEvent001, testing::ext::TestSize.Level1)
{
    const std::vector<SecurityCollector::SecurityEventRuler> rules;
    std::vector<SecurityCollector::SecurityEvent> events;
    int ret = SecurityCollector::CollectorManager::GetInstance().QuerySecurityEvent(rules, events);
    EXPECT_EQ(ret, SecurityCollector::BAD_PARAM);
}

/**
 * @tc.name: GetSubscribeInfo001
 * @tc.desc: ICollectorSubscriber GetSubscribeInfo
 * @tc.type: FUNC
 * @tc.require: AR000IENKB
 */
HWTEST_F(CollectorInterfaceTest, GetSubscribeInfo001, testing::ext::TestSize.Level1)
{
    int64_t eventId = 1;
    std::string version = "version";
    std::string content = "content";
    std::string extra = "extra";
    SecurityCollector::Event event = {eventId, version, content, extra};
    int64_t duration = 2;
    SecurityCollector::CollectorSubscriberTestImpl subscriber{event, duration, true};
    SecurityCollector::SecurityCollectorSubscribeInfo result = subscriber.GetSubscribeInfo();
    EXPECT_EQ(event.eventId, result.GetEvent().eventId);
    EXPECT_EQ(event.version, result.GetEvent().version);
    EXPECT_EQ(event.content, result.GetEvent().content);
    EXPECT_EQ(event.extra, result.GetEvent().extra);
}

/**
 * @tc.name: Subscribe001
 * @tc.desc: CollectorManager Subscribe
 * @tc.type: FUNC
 * @tc.require: AR000IENKB
 */
HWTEST_F(CollectorInterfaceTest, Subscribe001, testing::ext::TestSize.Level1)
{
    int ret = SecurityCollector::CollectorManager::GetInstance().Subscribe(nullptr);
    EXPECT_EQ(ret, SecurityCollector::BAD_PARAM);
}

HWTEST_F(CollectorInterfaceTest, Subscribe002, testing::ext::TestSize.Level1)
{
    SecurityCollector::CollectorManager manager {};
    SecurityCollector::Event event {};
    auto subscriber = std::make_shared<SecurityGuardTest::SecurityCollectorSubscriber>(event);
    sptr<SecurityCollector::SecurityCollectorManagerCallbackService> callback =
            new (std::nothrow) SecurityCollector::SecurityCollectorManagerCallbackService(nullptr);
    manager.eventListeners_.insert({subscriber, callback});
    int ret = manager.Subscribe(subscriber);
    EXPECT_EQ(ret, SecurityCollector::BAD_PARAM);
}

HWTEST_F(CollectorInterfaceTest, Subscribe003, testing::ext::TestSize.Level1)
{
    SecurityCollector::CollectorManager manager {};
    SecurityCollector::Event event {};
    auto subscriber = std::make_shared<SecurityGuardTest::SecurityCollectorSubscriber>(event);
    int ret = manager.Subscribe(subscriber);
    EXPECT_EQ(ret, SecurityCollector::BAD_PARAM);
}
/**
 * @tc.name: Unsubscribe001
 * @tc.desc: CollectorManager Unsubscribe
 * @tc.type: FUNC
 * @tc.require: AR000IENKB
 */
HWTEST_F(CollectorInterfaceTest, Unsubscribe001, testing::ext::TestSize.Level1)
{
    int ret = SecurityCollector::CollectorManager::GetInstance().Unsubscribe(nullptr);
    EXPECT_EQ(ret, SecurityCollector::BAD_PARAM);
}

HWTEST_F(CollectorInterfaceTest, Unsubscribe002, testing::ext::TestSize.Level1)
{
    SecurityCollector::CollectorManager manager {};
    SecurityCollector::Event event {};
    auto subscriber = std::make_shared<SecurityGuardTest::SecurityCollectorSubscriber>(event);
    sptr<SecurityCollector::SecurityCollectorManagerCallbackService> callback =
            new (std::nothrow) SecurityCollector::SecurityCollectorManagerCallbackService(nullptr);
    manager.eventListeners_.insert({subscriber, callback});
    int ret = manager.Subscribe(subscriber);
    EXPECT_EQ(ret, SecurityCollector::BAD_PARAM);
}

HWTEST_F(CollectorInterfaceTest, Unsubscribe003, testing::ext::TestSize.Level1)
{
    SecurityCollector::CollectorManager manager {};
    SecurityCollector::Event event {};
    auto subscriber = std::make_shared<SecurityGuardTest::SecurityCollectorSubscriber>(event);
    int ret = manager.Subscribe(subscriber);
    EXPECT_EQ(ret, SecurityCollector::BAD_PARAM);
}

/**
 * @tc.name: CollectorStart001
 * @tc.desc: ICollector Start
 * @tc.type: FUNC
 * @tc.require: AR20240110334295
 */
HWTEST_F(CollectorInterfaceTest, CollectorStart001, testing::ext::TestSize.Level1)
{
    SecurityCollector::CollectorManager::DeathRecipient recipient =
        SecurityCollector::CollectorManager::DeathRecipient();
    recipient.OnRemoteDied(nullptr);
    SecurityCollector::CollectorManager manager {};
    SecurityCollector::Event event {};
    SecurityCollector::SecurityCollectorSubscribeInfo subscriber(event, -1, false);
    sptr<SecurityCollector::SecurityCollectorManagerCallbackService> callback =
        new (std::nothrow) SecurityCollector::SecurityCollectorManagerCallbackService(nullptr);
    int ret = manager.CollectorStart(subscriber);
    EXPECT_EQ(ret, SecurityCollector::BAD_PARAM);
}

/**
 * @tc.name: CollectorStop001
 * @tc.desc: ICollector Start
 * @tc.type: FUNC
 * @tc.require: AR20240110334295
 */
HWTEST_F(CollectorInterfaceTest, CollectorStop001, testing::ext::TestSize.Level1)
{
    SecurityCollector::CollectorManager manager {};
    SecurityCollector::Event event {};
    SecurityCollector::SecurityCollectorSubscribeInfo subscriber(event, -1, false);
    sptr<SecurityCollector::SecurityCollectorManagerCallbackService> callback =
            new (std::nothrow) SecurityCollector::SecurityCollectorManagerCallbackService(nullptr);
    int ret = manager.CollectorStop(subscriber);
    EXPECT_EQ(ret, SecurityCollector::BAD_PARAM);
}

/**
 * @tc.name: QuerySecurityEventBatch001
 * @tc.desc: CollectorManager QuerySecurityEventBatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CollectorInterfaceTest, QuerySecurityEventBatch001, testing::ext::TestSize.Level1)
{
    const std::vector<SecurityCollector::SecurityEventRuler> rules;
    std::vector<SecurityCollector::SecurityEvent> events;
    std::vector<int64_t> failedEventIds;
    int ret = SecurityCollector::CollectorManager::GetInstance().QuerySecurityEventBatch(
        rules, events, failedEventIds);
    EXPECT_NE(ret, SecurityCollector::SUCCESS);
}
}