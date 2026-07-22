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

#include "security_guard_model_manager_test.h"


#include "file_ex.h"
#include "gmock/gmock.h"

#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "i_config_operate.h"
#define private public
#define protected public
#include "config_data_manager.h"
#include "i_model.h"
#include "model_manager.h"
#include "model_manager_impl.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityGuardTest;

namespace OHOS::Security::SecurityGuardTest {
namespace {
}

void SecurityGuardModelManagerTest::SetUpTestCase()
{
}

void SecurityGuardModelManagerTest::TearDownTestCase()
{
}

void SecurityGuardModelManagerTest::SetUp()
{
}

void SecurityGuardModelManagerTest::TearDown()
{
}

class MockModel : public IModel {
public:
    MOCK_METHOD1(Init, int32_t(std::shared_ptr<IModelManager>));
    MOCK_METHOD2(GetResult, std::string(uint32_t, const std::string &));
    MOCK_METHOD1(SubscribeResult, int32_t(std::shared_ptr<IModelResultListener>));
    MOCK_METHOD0(Release, void());
};

class MockModelManager : public IModelManager {
public:
    MOCK_METHOD0(GetConfigOperate, std::shared_ptr<IConfigOperate>());
    MOCK_METHOD1(GetDbOperate, std::shared_ptr<IDbOperate>(std::string));
    MOCK_METHOD2(SubscribeDb, int32_t(std::vector<int64_t>, std::shared_ptr<IDbListener>));
    MOCK_METHOD2(UnSubscribeDb, int32_t(std::vector<int64_t>, std::shared_ptr<IDbListener>));
};

class MockMyModelManager : public ModelManager {
public:
    MOCK_METHOD1(InitModel, int32_t(uint32_t));
};
class MockDbOperate : public IDbOperate {
public:
    MOCK_METHOD1(InsertEvent, int(SecEvent&));
    MOCK_METHOD1(QueryAllEvent, int(std::vector<SecEvent> &));
    MOCK_METHOD2(QueryRecentEventByEventId, int(int64_t, SecEvent &));
    MOCK_METHOD2(QueryRecentEventByEventId, int(const std::vector<int64_t> &, std::vector<SecEvent> &));
    MOCK_METHOD2(QueryEventByEventId, int(int64_t, std::vector<SecEvent> &));
    MOCK_METHOD2(QueryEventByEventId, int(std::vector<int64_t> &, std::vector<SecEvent> &));
    MOCK_METHOD4(QueryEventByEventIdAndDate, int(std::vector<int64_t> &,
        std::vector<SecEvent> &, std::string, std::string));
    MOCK_METHOD2(QueryEventByEventType, int(int32_t, std::vector<SecEvent> &));
    MOCK_METHOD2(QueryEventByLevel, int(int32_t, std::vector<SecEvent> &));
    MOCK_METHOD2(QueryEventByOwner, int(std::string, std::vector<SecEvent> &));
    MOCK_METHOD0(CountAllEvent, int64_t());
    MOCK_METHOD1(CountEventByEventId, int64_t(int64_t));
    MOCK_METHOD2(DeleteOldEventByEventId, int(int64_t, int64_t));
    MOCK_METHOD1(DeleteAllEventByEventId, int(int64_t));
};

class MockConfigOperate : public IConfigOperate {
public:
    MOCK_METHOD2(GetModelConfig, bool(uint32_t, ModelCfg &));
    MOCK_METHOD2(GetEventConfig, bool(int64_t, EventCfg &));
};

HWTEST_F(SecurityGuardModelManagerTest, TestModelManagerImpl001, TestSize.Level0)
{
    auto impl = std::make_shared<ModelManagerImpl>();
    std::shared_ptr<IDbOperate> oper = impl->GetDbOperate("risk_event");
    EXPECT_FALSE(oper == nullptr);
    oper = impl->GetDbOperate("audit_event");
    EXPECT_FALSE(oper == nullptr);
    oper = impl->GetDbOperate("test_table");
    EXPECT_TRUE(oper == nullptr);
}

HWTEST_F(SecurityGuardModelManagerTest, TestModelManagerInit001, TestSize.Level0)
{
    std::vector<uint32_t> emptyVector{};
    std::vector<uint32_t> vector{0};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetAllModelIds).Times(AtLeast(5)).WillOnce(Return(emptyVector))
        .WillRepeatedly(Return(vector));
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetModelConfig).Times(AtLeast(5)).WillOnce(Return(false))
        .WillOnce([](uint32_t modelId, ModelCfg &config) {
            config.startMode = 0;
            return true;
        })
        .WillOnce([](uint32_t modelId, ModelCfg &config) {
            config.startMode = 1;
            config.modelId = 0;
            return true;
        })
        .WillRepeatedly([](uint32_t modelId, ModelCfg &config) {
            config.startMode = 1;
            config.modelId = 3001000003;
            return true;
        });
    ModelManager::GetInstance().Init();
    ModelManager::GetInstance().Init();
    ModelManager::GetInstance().Init();
    ModelManager::GetInstance().Init();
    ModelManager::GetInstance().Init();
    EXPECT_TRUE(ModelManager::GetInstance().InitModel(0) != SUCCESS);
}

HWTEST_F(SecurityGuardModelManagerTest, TestModelManagerInitModel001, TestSize.Level0)
{
    MockModel *model = new MockModel();
    EXPECT_CALL(*model, Release()).Times(1);
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetModelConfig).Times(1).WillOnce(Return(false));
    std::unique_ptr<ModelAttrs> attr = std::make_unique<ModelAttrs>();
    attr->SetModelApi(model);
    ModelManager::GetInstance().modelIdApiMap_[8888] = std::move(attr);
    ModelManager::GetInstance().modelIdApiMap_[9999] = nullptr;
    ModelManager::GetInstance().Release(9999);
    EXPECT_TRUE(ModelManager::GetInstance().InitModel(8888) != SUCCESS);
}

HWTEST_F(SecurityGuardModelManagerTest, TestModelManagerInitModel002, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetModelConfig).Times(AtLeast(6))
        .WillOnce([](uint32_t modelId, ModelCfg &config) {
            config.path = "/system/lib64/sg_test";
            return true;
        })
        .WillOnce([](uint32_t modelId, ModelCfg &config) {
            config.path = "/system/lib64/libsg_collector_sdk.z.so";
            return true;
        })
        .WillOnce([](uint32_t modelId, ModelCfg &config) {
            config.path = "/system/lib64/libsg_system_risk_detection.z.so";
            return true;
        })
        .WillOnce([](uint32_t modelId, ModelCfg &config) {
            config.startMode = NOT_SUPPORT;
            return false;
        })
        .WillOnce([](uint32_t modelId, ModelCfg &config) {
            config.startMode = NOT_SUPPORT;
            return true;
        })
        .WillRepeatedly([](uint32_t modelId, ModelCfg &config) {
            config.startMode = START_ON_DEMAND;
            return true;
        });
    ModelManager::GetInstance().InitModel(9999);
    ModelManager::GetInstance().GetResult(9999, "");
    ModelManager::GetInstance().SubscribeResult(9999, nullptr);
    ModelManager::GetInstance().Release(9999);
    ModelManager::GetInstance().InitModel(9999);
    ModelManager::GetInstance().GetResult(9999, "");
    ModelManager::GetInstance().SubscribeResult(9999, nullptr);
    ModelManager::GetInstance().Release(9999);
    ModelManager::GetInstance().InitModel(9999);
    ModelManager::GetInstance().GetResult(9999, "");
    ModelManager::GetInstance().GetResult(9999, "");
    ModelManager::GetInstance().GetResult(9999, "");
    ModelManager::GetInstance().SubscribeResult(9999, nullptr);
    ModelManager::GetInstance().Release(9999);
    EXPECT_TRUE(ModelManager::GetInstance().InitModel(9999) != SUCCESS);
}

HWTEST_F(SecurityGuardModelManagerTest, TestModelManagerStartSecurityModel001, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetModelConfig)
    .WillOnce([](uint32_t modelId, ModelCfg &config) {
        config.path = "/system/lib64/sg_test";
        return false;
    });
    EXPECT_EQ(ModelManager::GetInstance().StartSecurityModel(111, "test"), NOT_FOUND);
}

HWTEST_F(SecurityGuardModelManagerTest, TestModelManagerStartSecurityModel002, TestSize.Level0)
{
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetModelConfig)
    .WillOnce([](uint32_t modelId, ModelCfg &config) {
        config.path = "/system/lib64/sg_test";
        return true;
    });
    EXPECT_EQ(ModelManager::GetInstance().StartSecurityModel(111, "test"), FILE_ERR);
}

HWTEST_F(SecurityGuardModelManagerTest, TestModelManagerGetResult002, TestSize.Level0)
{
    MockMyModelManager manager {};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetModelConfig)
    .WillOnce([](uint32_t modelId, ModelCfg &config) {
        config.path = "/system/lib64/sg_test";
        config.startMode = START_ON_DEMAND;
        return true;
    });
    EXPECT_CALL(manager, InitModel)
    .WillOnce([](uint32_t modelId) {
        return SUCCESS;
    });
    EXPECT_EQ(manager.GetResult(111, "test"), "unknown");
}

HWTEST_F(SecurityGuardModelManagerTest, TestModelManagerGetResult003, TestSize.Level0)
{
    MockMyModelManager manager {};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetModelConfig)
    .WillOnce([](uint32_t modelId, ModelCfg &config) {
        config.path = "/system/lib64/sg_test";
        config.startMode = START_ON_DEMAND;
        return true;
    });
    EXPECT_CALL(manager, InitModel)
    .WillOnce([](uint32_t modelId) {
        return FAILED;
    });
    EXPECT_EQ(manager.GetResult(111, "test"), "unknown");
}

HWTEST_F(SecurityGuardModelManagerTest, TestModelManagerGetResult004, TestSize.Level0)
{
    MockMyModelManager manager {};
    EXPECT_CALL(ConfigDataManager::GetInstance(), GetModelConfig)
    .WillOnce([](uint32_t modelId, ModelCfg &config) {
        config.path = "/system/lib64/sg_test";
        config.startMode = NOT_SUPPORT;
        return true;
    }).WillOnce([](uint32_t modelId, ModelCfg &config) {
        config.path = "/system/lib64/sg_test";
        config.startMode = NOT_SUPPORT;
        return true;
    });
    MockModel *model = new MockModel();
    EXPECT_CALL(*model, Release()).Times(1);
    std::unique_ptr<ModelAttrs> attr = std::make_unique<ModelAttrs>();
    attr->SetModelApi(model);
    ModelManager::GetInstance().modelIdApiMap_[8888] = std::move(attr);
    EXPECT_EQ(manager.GetResult(8888, "test"), "unknown");
    EXPECT_TRUE(ModelManager::GetInstance().InitModel(8888) != SUCCESS);
}
class ModelResultListener : public IModelResultListener {
    void OnChange(std::string result) {};
};

HWTEST_F(SecurityGuardModelManagerTest, TestModelManagerSubscribeResult002, TestSize.Level0)
{
    MockMyModelManager manager {};
    EXPECT_CALL(manager, InitModel)
    .WillOnce([](uint32_t modelId) {
        return SUCCESS;
    });
    auto listener = std::make_shared<ModelResultListener>();
    EXPECT_EQ(manager.SubscribeResult(111, listener), FAILED);
}

HWTEST_F(SecurityGuardModelManagerTest, TestModelManagerSubscribeResult003, TestSize.Level0)
{
    MockMyModelManager manager {};
    EXPECT_EQ(manager.SubscribeResult(111, nullptr), BAD_PARAM);
}

HWTEST_F(SecurityGuardModelManagerTest, TestModelManagerStartSecurityModel003, TestSize.Level0)
{
    MockMyModelManager manager {};
    EXPECT_CALL(manager, InitModel)
    .WillOnce([](uint32_t modelId) {
        return SUCCESS;
    });
    EXPECT_EQ(manager.StartSecurityModel(111, "test"), FAILED);
}
}