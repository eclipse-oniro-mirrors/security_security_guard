/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "detect_plugin_manager_test.h"
#include "gmock/gmock.h"
#include "json_util.h"
#define private public
#define protected public
#include "detect_plugin_manager.h"
#include "i_detect_plugin.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityGuardTest;
namespace OHOS::Security::SecurityGuardTest {
void DetectPluginManagerTest::SetUpTestCase()
{
}
void DetectPluginManagerTest::TearDownTestCase()
{
}
void DetectPluginManagerTest::SetUp()
{
}
void DetectPluginManagerTest::TearDown()
{
}

class MockDetectPlugin : public IDetectPlugin {
public:
    MOCK_METHOD0(Init, bool());
    MOCK_METHOD0(Destroy, void());
    MOCK_METHOD3(HandleEvent, void(int64_t, const std::string&, const std::string&));
};

HWTEST_F(DetectPluginManagerTest, LoadPlugins001, TestSize.Level1) {
    DetectPluginManager::getInstance().LoadAllPlugins("/data/test/unittest/resource/detect_plugin.json");
    std::unordered_set<int64_t> depEventIds;
    DetectPluginManager::PluginCfg pluginCfg = {
        "libsg_collect_service_database.z.so",
        "/system/lib64/libsg_collect_service_database.z.so",
        depEventIds,
        "6.0"
    };
    DetectPluginManager::PluginCfg pluginCfgOpen = {
        "libsg_collect_service_database.z.so",
        "/system/lib/libsg_collect_service_database.z.so",
        depEventIds,
        "6.0"
    };
    DetectPluginManager::getInstance().LoadPlugin(pluginCfg);
    DetectPluginManager::getInstance().LoadPlugin(pluginCfgOpen);
    EXPECT_TRUE(DetectPluginManager::getInstance().eventIdMap_.count(-1) == 0);
}

HWTEST_F(DetectPluginManagerTest, DispatchEvent001, TestSize.Level1) {
    MockDetectPlugin *detectPlugin = new MockDetectPlugin();
    EXPECT_CALL(*detectPlugin, HandleEvent).Times(1);
    std::shared_ptr<DetectPluginManager::DetectPluginAttrs> detectPluginAttrs =
        std::make_shared<DetectPluginManager::DetectPluginAttrs>();
    detectPluginAttrs->SetInstance(detectPlugin);
    DetectPluginManager::getInstance().eventIdMap_[0x02C000000].emplace_back(detectPluginAttrs);
    SecurityCollector::Event event = {
        .eventId = 0x02C000000,
        .version = "1.0",
        .content = "test",
        .timestamp = "1749176423802"
    };
    DetectPluginManager::getInstance().DispatchEvent(event);
    EXPECT_TRUE(DetectPluginManager::getInstance().eventIdMap_.count(event.eventId) > 0);
}

HWTEST_F(DetectPluginManagerTest, DispatchEvent002, TestSize.Level1) {
    SecurityCollector::Event event = {
        .eventId = 0x0000,
        .version = "1.0",
        .content = "error",
        .timestamp = "1749176423802"
    };
    DetectPluginManager::getInstance().DispatchEvent(event);
    EXPECT_TRUE(DetectPluginManager::getInstance().eventIdMap_.count(event.eventId) == 0);
}

HWTEST_F(DetectPluginManagerTest, ParsePluginConfig001, TestSize.Level1) {
    EXPECT_TRUE(DetectPluginManager::getInstance().ParsePluginConfig(
        "/data/test/unittest/resource/detect_plugin.json"));
}

HWTEST_F(DetectPluginManagerTest, ParsePluginConfig002, TestSize.Level1) {
    EXPECT_FALSE(DetectPluginManager::getInstance().ParsePluginConfig("test.json"));
}

HWTEST_F(DetectPluginManagerTest, ParsePluginConfig003, TestSize.Level1) {
    EXPECT_TRUE(DetectPluginManager::getInstance().ParsePluginConfig(
        "/data/test/unittest/resource/detect_plugin.json"));
}

HWTEST_F(DetectPluginManagerTest, ParsePluginDepEventIds001, TestSize.Level1) {
    std::unordered_set<int64_t> depEventIds;
    cJSON *plugin = cJSON_CreateObject();
    std::vector<std::string> inVector = {"test"};
    JsonUtil::AddStrArrayInfo(plugin, inVector, "depEventIds");
    EXPECT_FALSE(DetectPluginManager::getInstance().ParsePluginDepEventIds(plugin, depEventIds));
}

HWTEST_F(DetectPluginManagerTest, ParsePluginDepEventIds002, TestSize.Level1) {
    std::unordered_set<int64_t> depEventIds;
    cJSON *plugin = cJSON_CreateObject();
    EXPECT_FALSE(DetectPluginManager::getInstance().ParsePluginDepEventIds(plugin, depEventIds));
}

HWTEST_F(DetectPluginManagerTest, ParsePluginConfigObjArray001, TestSize.Level1) {
    DetectPluginManager::getInstance().plugins_.clear();
    cJSON *plugin = cJSON_CreateObject();
    DetectPluginManager::getInstance().ParsePluginConfigObjArray(plugin);
    EXPECT_TRUE(DetectPluginManager::getInstance().plugins_.size() == 0);
}

HWTEST_F(DetectPluginManagerTest, ParsePluginConfigObjArray002, TestSize.Level1) {
    cJSON *plugin = cJSON_CreateObject();
    std::vector<std::string> inVector = {"0x02C000000"};
    JsonUtil::AddStrArrayInfo(plugin, inVector, "depEventIds");
    JsonUtil::AddString(plugin, "pluginName", "test.z.so");
    std::unordered_set<int64_t> depEventIds;
    DetectPluginManager::PluginCfg pluginCfg = {
        "test.z.so",
        "/system/lib64/",
        depEventIds,
        "6.0"
    };
    DetectPluginManager::getInstance().plugins_.emplace_back(pluginCfg);
    DetectPluginManager::getInstance().ParsePluginConfigObjArray(plugin);
    EXPECT_TRUE(DetectPluginManager::getInstance().plugins_.size() != 0);
}

HWTEST_F(DetectPluginManagerTest, CheckPluginNameAndSize001, TestSize.Level1) {
    std::unordered_set<int64_t> depEventIds;
    DetectPluginManager::PluginCfg pluginCfg = {
        "test.z.so",
        "/system/lib64/",
        depEventIds,
        "6.0"
    };
    DetectPluginManager::getInstance().plugins_.emplace_back(pluginCfg);
    EXPECT_FALSE(DetectPluginManager::getInstance().CheckPluginNameAndSize(pluginCfg));
}

HWTEST_F(DetectPluginManagerTest, CheckPluginNameAndSize002, TestSize.Level1) {
    std::unordered_set<int64_t> depEventIds;
    DetectPluginManager::PluginCfg pluginCfg = {
        "test.z.so",
        "/system/lib64/",
        depEventIds,
        "6.0"
    };
    for (int i = 0; i < 20; i++) {
        DetectPluginManager::getInstance().plugins_.emplace_back(pluginCfg);
    }
    EXPECT_FALSE(DetectPluginManager::getInstance().CheckPluginNameAndSize(pluginCfg));
}

// Covers StopRetryTask: idempotent when no retry thread exists (also converges
// any thread left by earlier LoadAllPlugins cases).
HWTEST_F(DetectPluginManagerTest, StopRetryTask001, TestSize.Level1) {
    DetectPluginManager::getInstance().StopRetryTask();
    DetectPluginManager::getInstance().StopRetryTask(); // 幂等
    EXPECT_FALSE(DetectPluginManager::getInstance().retryThread_.joinable());
    EXPECT_TRUE(DetectPluginManager::getInstance().isStopRetry_.load());
    // 恢复状态，避免影响后续用例
    DetectPluginManager::getInstance().isStopRetry_.store(false);
}

// Covers StopRetryTask: spawned retry thread exits at the next stop checkpoint
// (1s sleep slice) and join completes; stop flag stays set.
HWTEST_F(DetectPluginManagerTest, StopRetryTask002, TestSize.Level1) {
    DetectPluginManager::getInstance().StopRetryTask(); // 先收敛既有线程，避免覆盖 joinable 线程
    DetectPluginManager::getInstance().isStopRetry_.store(false);
    DetectPluginManager::getInstance().isFailedEventStartRetry_ = false;
    DetectPluginManager::getInstance().failedEventIdset_.insert(0x9999);
    DetectPluginManager::getInstance().retryThread_ = ffrt::thread([]() {
        DetectPluginManager::getInstance().RetrySubscriptionTask();
    });
    EXPECT_TRUE(DetectPluginManager::getInstance().retryThread_.joinable());
    DetectPluginManager::getInstance().StopRetryTask();
    EXPECT_FALSE(DetectPluginManager::getInstance().retryThread_.joinable()); // 已 join
    EXPECT_TRUE(DetectPluginManager::getInstance().isStopRetry_.load());
    // 清理状态，避免影响其他用例
    DetectPluginManager::getInstance().failedEventIdset_.clear();
    DetectPluginManager::getInstance().isFailedEventStartRetry_ = false;
}
}