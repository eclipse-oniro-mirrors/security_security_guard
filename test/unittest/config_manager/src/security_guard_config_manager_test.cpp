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

#include "security_guard_config_manager_test.h"

#include <unistd.h>

#include "file_ex.h"
#include "gmock/gmock.h"
#include "nlohmann/json.hpp"
#include <thread>
#include <fstream>
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "security_event_info.h"
#include "json_cfg.h"
#define private public
#define protected public
#include "base_config.h"
#include "config_data_manager.h"
#include "i_model_info.h"
#include "config_define.h"
#include "config_manager.h"
#include "config_operator.h"
#include "config_subscriber.h"
#include "event_config.h"
#include "model_cfg_marshalling.h"
#include "model_config.h"
#include "security_guard_log.h"
#include "event_group_config.h"
#include "json_util.h"
#include "file_util.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityGuardTest;
using namespace OHOS::Security::SecurityGuard::FileUtil;
using namespace OHOS::Security::SecurityGuard::JsonUtil;

namespace OHOS::Security::SecurityGuardTest {

void SecurityGuardConfigManagerTest::SetUpTestCase()
{
    static const char *permission[] = { "ohos.permission.securityguard.REPORT_SECURITY_INFO" };
    uint64_t tokenId;
    NativeTokenInfoParams infoParams = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = permission,
        .acls = nullptr,
        .processName = "security_guard",
        .aplStr = "system_basic",
    };
    tokenId = GetAccessTokenId(&infoParams);
    SetSelfTokenID(tokenId);
}

void SecurityGuardConfigManagerTest::TearDownTestCase()
{
}

void SecurityGuardConfigManagerTest::SetUp()
{
}

void SecurityGuardConfigManagerTest::TearDown()
{
}

class MockBaseConfig : public BaseConfig {
public:
    MockBaseConfig() = default;
    ~MockBaseConfig() override = default;
    MOCK_METHOD0(Check, bool());
    MOCK_METHOD1(Load, bool(int));
    MOCK_METHOD0(Parse, bool());
    MOCK_METHOD0(Update, bool());
};

class TestBaseConfig : public BaseConfig {
public:
    TestBaseConfig() = default;
    ~TestBaseConfig() override = default;
    MOCK_METHOD1(Load, bool(int));
    MOCK_METHOD0(Parse, bool());
    MOCK_METHOD0(Update, bool());
};

HWTEST_F(SecurityGuardConfigManagerTest, TestConfigOperator001, TestSize.Level1)
{
    MockBaseConfig config;
    auto configOptor = std::make_unique<ConfigOperator>(config);
    EXPECT_CALL(config, Load).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(config, Check).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(config, Parse).WillOnce(Return(false)).WillRepeatedly(Return(true));
    bool success = configOptor->Init();
    EXPECT_FALSE(success);
    success = configOptor->Init();
    EXPECT_FALSE(success);
    success = configOptor->Init();
    EXPECT_FALSE(success);
    success = configOptor->Init();
    EXPECT_TRUE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestConfigOperator002, TestSize.Level1)
{
    MockBaseConfig config;
    auto configOptor = std::make_unique<ConfigOperator>(config);
    EXPECT_CALL(config, Load).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(config, Check).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(config, Update).WillOnce(Return(false)).WillRepeatedly(Return(true));
    bool success = configOptor->Update();
    EXPECT_FALSE(success);
    success = configOptor->Update();
    EXPECT_FALSE(success);
    success = configOptor->Update();
    EXPECT_FALSE(success);
    success = configOptor->Update();
    EXPECT_TRUE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestBaseConfig001, TestSize.Level1)
{
    TestBaseConfig config;
    config.stream_.close();
    bool success = config.Check();
    EXPECT_FALSE(success);
    config.stream_.open("test.txt");
    success = config.Check();
    EXPECT_FALSE(success);
    config.stream_.open("/data/test/unittest/resource/stream_empty.txt");
    success = config.Check();
    EXPECT_FALSE(success);
    config.stream_.open("/data/test/unittest/resource/stream_not_empty.txt");
    success = config.Check();
    EXPECT_TRUE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestConfigDataManager001, TestSize.Level1)
{
    EventCfg config = {};
    std::string eventName = "test eventName";
    config.eventName = eventName;
    ConfigDataManager::GetInstance().InsertEventMap(config.eventId, config);
    EventCfg outConfig = {};
    bool success = ConfigDataManager::GetInstance().GetEventConfig(config.eventId, outConfig);
    EXPECT_TRUE(success);
    EXPECT_TRUE(outConfig.eventName == config.eventName);
    std::vector<int64_t> eventIds = ConfigDataManager::GetInstance().GetAllEventIds();
    EXPECT_TRUE(eventIds.size() == 1);
    EXPECT_TRUE(eventIds[0] == 0);
    ConfigDataManager::GetInstance().ResetEventMap();
    success = ConfigDataManager::GetInstance().GetEventConfig(config.eventId, outConfig);
    EXPECT_FALSE(success);
    eventIds = ConfigDataManager::GetInstance().GetAllEventIds();
    EXPECT_TRUE(eventIds.size() == 0);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestConfigDataManager002, TestSize.Level1)
{
    ModelCfg config = {};
    std::string path = "test path";
    config.path = path;
    ConfigDataManager::GetInstance().InsertModelMap(config.modelId, config);
    ModelCfg outConfig = {};
    bool success = ConfigDataManager::GetInstance().GetModelConfig(config.modelId, outConfig);
    EXPECT_TRUE(success);
    EXPECT_TRUE(outConfig.path == config.path);
    ConfigDataManager::GetInstance().ResetModelMap();
    success = ConfigDataManager::GetInstance().GetModelConfig(config.modelId, outConfig);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardConfigManagerTest, TestEventConfig002, TestSize.Level1)
{
    ConfigDataManager::GetInstance().ResetEventMap();
    ConfigDataManager::GetInstance().ResetModelMap();
    EventConfig config;
    bool success = config.Parse();
    EXPECT_FALSE(success);
    config.stream_.open("/data/test/unittest/resource/security_guard_preset_event.cfg");
    success = config.Parse();
    EXPECT_TRUE(success);
    EventCfg eventCfg;
    eventCfg.eventId = 2;
    success = ConfigDataManager::GetInstance().GetEventConfig(eventCfg.eventId, eventCfg);
    EXPECT_TRUE(success);
    EXPECT_TRUE(eventCfg.eventName == "preset_event");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestEventConfig003, TestSize.Level1)
{
    ConfigDataManager::GetInstance().ResetEventMap();
    ConfigDataManager::GetInstance().ResetModelMap();
    EventConfig config;
    bool success = config.Parse();
    EXPECT_FALSE(success);
    config.stream_.open("/data/test/unittest/resource/security_guard_update_event.cfg");
    EXPECT_TRUE(config.stream_.is_open());
    success = config.Parse();
    EXPECT_TRUE(success);
    EventCfg eventCfg;
    eventCfg.eventId = 3;
    success = ConfigDataManager::GetInstance().GetEventConfig(eventCfg.eventId, eventCfg);
    EXPECT_TRUE(success);
    EXPECT_TRUE(eventCfg.eventName == "update_event");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestEventConfig001, TestSize.Level1)
{
    EventConfig config;
    bool success = config.Load(INIT_MODE);
    EXPECT_TRUE(success);
    EXPECT_TRUE(config.Load(UPDATE_MODE));
    config.Update();
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelConfig001, TestSize.Level1)
{
    ModelConfig config;
    bool success = config.Load(INIT_MODE);
    EXPECT_TRUE(success);
    EXPECT_TRUE(config.Load(UPDATE_MODE));
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelConfig002, TestSize.Level1)
{
    ConfigDataManager::GetInstance().ResetEventMap();
    ConfigDataManager::GetInstance().ResetModelMap();
    ModelConfig config;
    bool success = config.Parse();
    EXPECT_FALSE(success);
    config.stream_.open("/data/test/unittest/resource/security_guard_preset_model.cfg");
    EXPECT_TRUE(config.stream_.is_open());
    success = config.Parse();
    EXPECT_TRUE(success);
    ModelCfg modelCfg;
    modelCfg.modelId = 2;
    success = ConfigDataManager::GetInstance().GetModelConfig(modelCfg.modelId, modelCfg);
    EXPECT_TRUE(success);
    EXPECT_TRUE(modelCfg.path == "preset_model");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelConfig003, TestSize.Level1)
{
    ConfigDataManager::GetInstance().ResetEventMap();
    ConfigDataManager::GetInstance().ResetModelMap();
    ModelConfig config;
    bool success = config.Parse();
    EXPECT_FALSE(success);
    config.stream_.open("/data/test/unittest/resource/security_guard_update_model.cfg");
    EXPECT_TRUE(config.stream_.is_open());
    success = config.Parse();
    EXPECT_TRUE(success);
    ModelCfg modelCfg;
    modelCfg.modelId = 3;
    success = ConfigDataManager::GetInstance().GetModelConfig(modelCfg.modelId, modelCfg);
    EXPECT_TRUE(success);
    EXPECT_TRUE(modelCfg.path == "update_model");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelConfig004, TestSize.Level1)
{
    ConfigDataManager::GetInstance().ResetEventMap();
    ConfigDataManager::GetInstance().ResetModelMap();
    ModelConfig config;
    nlohmann::json jsonObj;
    ModelCfg modelCfg;
    to_json(jsonObj, modelCfg);
    DataMgrCfgSt dataMgrCfg{};
    to_json(jsonObj, dataMgrCfg);
    from_json(jsonObj, dataMgrCfg);
    SecEvent eventDataSt{};
    to_json(jsonObj, eventDataSt);
    EventContentSt eventContentSt{};
    to_json(jsonObj, eventContentSt);
    from_json(jsonObj, eventContentSt);
    EventCfg eventCfg{};
    jsonObj["modelId"] = "xxx";
    from_json(jsonObj, modelCfg);
    jsonObj["eventId"] = "xxx";
    from_json(jsonObj, eventCfg);
    bool success = config.Parse();
    EXPECT_FALSE(success);
    config.stream_.open("/data/test/unittest/resource/security_guard_preset_model.cfg");
    EXPECT_TRUE(config.stream_.is_open());
    EXPECT_TRUE(config.Update());
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelConfig005, TestSize.Level1)
{
    ConfigDataManager::GetInstance().ResetEventMap();
    ConfigDataManager::GetInstance().ResetModelMap();
    ConfigDataManager::GetInstance().GetAllModelIds();
    ConfigDataManager::GetInstance().ResetEventToTableMap();
    EXPECT_TRUE(ConfigDataManager::GetInstance().GetTableFromEventId(0).empty());
    EXPECT_TRUE(ConfigDataManager::GetInstance().GetAllEventConfigs().empty());
}

HWTEST_F(SecurityGuardConfigManagerTest, TestConfigSubsciber003, TestSize.Level1)
{
    EXPECT_TRUE(
        ConfigSubscriber::UpdateConfig(CONFIG_CACHE_FILES[EVENT_CFG_INDEX]));
    EXPECT_TRUE(
        ConfigSubscriber::UpdateConfig(CONFIG_CACHE_FILES[MODEL_CFG_INDEX]));
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling001, TestSize.Level1)
{
    nlohmann::json jsonObj;
    SecurityGuard::AppDetectionCfg cfg = jsonObj.get<SecurityGuard::AppDetectionCfg>();
    EXPECT_TRUE(cfg.detectionCategory == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling002, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["detectionCategory"] = 0;
    SecurityGuard::AppDetectionCfg cfg = jsonObj.get<SecurityGuard::AppDetectionCfg>();
    EXPECT_TRUE(cfg.detectionCategory == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling003, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["detectionCategory"] = "detectionCategory";
    SecurityGuard::AppDetectionCfg cfg = jsonObj.get<SecurityGuard::AppDetectionCfg>();
    EXPECT_TRUE(cfg.detectionCategory == "detectionCategory");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling004, TestSize.Level1)
{
    nlohmann::json jsonObj;
    SecurityGuard::Field field = jsonObj.get<SecurityGuard::Field>();
    EXPECT_TRUE(field.fieldName == "");
    EXPECT_TRUE(field.fieldType == "");
    EXPECT_TRUE(field.value == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling005, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["fieldName"] = 0;
    SecurityGuard::Field field = jsonObj.get<SecurityGuard::Field>();
    EXPECT_TRUE(field.fieldName == "");
    EXPECT_TRUE(field.fieldType == "");
    EXPECT_TRUE(field.value == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling006, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["fieldName"] = 0;
    jsonObj["fieldType"] = 0;
    SecurityGuard::Field field = jsonObj.get<SecurityGuard::Field>();
    EXPECT_TRUE(field.fieldName == "");
    EXPECT_TRUE(field.fieldType == "");
    EXPECT_TRUE(field.value == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling007, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["fieldName"] = 0;
    jsonObj["fieldType"] = 0;
    jsonObj["value"] = 0;
    SecurityGuard::Field field = jsonObj.get<SecurityGuard::Field>();
    EXPECT_TRUE(field.fieldName == "");
    EXPECT_TRUE(field.fieldType == "");
    EXPECT_TRUE(field.value == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling008, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["fieldName"] = "fieldName";
    jsonObj["fieldType"] = 0;
    jsonObj["value"] = 0;
    SecurityGuard::Field field = jsonObj.get<SecurityGuard::Field>();
    EXPECT_TRUE(field.fieldName == "");
    EXPECT_TRUE(field.fieldType == "");
    EXPECT_TRUE(field.value == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling009, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["fieldName"] = "fieldName";
    jsonObj["fieldType"] = "fieldType";
    jsonObj["value"] = 0;
    SecurityGuard::Field field = jsonObj.get<SecurityGuard::Field>();
    EXPECT_TRUE(field.fieldName == "");
    EXPECT_TRUE(field.fieldType == "");
    EXPECT_TRUE(field.value == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling010, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["fieldName"] = "fieldName";
    jsonObj["fieldType"] = "fieldType";
    jsonObj["value"] = "value";
    SecurityGuard::Field field = jsonObj.get<SecurityGuard::Field>();
    EXPECT_TRUE(field.fieldName == "fieldName");
    EXPECT_TRUE(field.fieldType == "fieldType");
    EXPECT_TRUE(field.value == "value");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling011, TestSize.Level1)
{
    nlohmann::json jsonObj;
    SecurityGuard::Rule rule = jsonObj.get<SecurityGuard::Rule>();
    EXPECT_TRUE(rule.eventId == 0);
    EXPECT_TRUE(rule.fields.empty());
    EXPECT_TRUE(rule.fieldsRelation == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling012, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["eventId"] = "";
    SecurityGuard::Rule rule = jsonObj.get<SecurityGuard::Rule>();
    EXPECT_TRUE(rule.eventId == 0);
    EXPECT_TRUE(rule.fields.empty());
    EXPECT_TRUE(rule.fieldsRelation == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling013, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["eventId"] = "";
    jsonObj["fields"] = 0;
    SecurityGuard::Rule rule = jsonObj.get<SecurityGuard::Rule>();
    EXPECT_TRUE(rule.eventId == 0);
    EXPECT_TRUE(rule.fields.empty());
    EXPECT_TRUE(rule.fieldsRelation == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling014, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["eventId"] = "";
    jsonObj["fields"] = 0;
    jsonObj["fieldsRelation"] = 0;
    SecurityGuard::Rule rule = jsonObj.get<SecurityGuard::Rule>();
    EXPECT_TRUE(rule.eventId == 0);
    EXPECT_TRUE(rule.fields.empty());
    EXPECT_TRUE(rule.fieldsRelation == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling015, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["eventId"] = 0;
    jsonObj["fields"] = 0;
    jsonObj["fieldsRelation"] = 0;
    SecurityGuard::Rule rule = jsonObj.get<SecurityGuard::Rule>();
    EXPECT_TRUE(rule.eventId == 0);
    EXPECT_TRUE(rule.fields.empty());
    EXPECT_TRUE(rule.fieldsRelation == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling016, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["eventId"] = 0;
    jsonObj["fields"] = 0;
    jsonObj["fieldsRelation"] = 0;
    SecurityGuard::Rule rule = jsonObj.get<SecurityGuard::Rule>();
    EXPECT_TRUE(rule.eventId == 0);
    EXPECT_TRUE(rule.fields.empty());
    EXPECT_TRUE(rule.fieldsRelation == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling017, TestSize.Level1)
{
    nlohmann::json jsonObj;
    nlohmann::json jsonField;
    jsonField["fieldName"] = "fieldName";
    jsonField["fieldType"] = "fieldType";
    jsonField["value"] = "value";
    jsonObj["eventId"] = 0;
    jsonObj["fields"] = {jsonField, jsonField};
    jsonObj["fieldsRelation"] = 0;
    SecurityGuard::Rule rule = jsonObj.get<SecurityGuard::Rule>();
    EXPECT_TRUE(rule.eventId == 0);
    EXPECT_TRUE(rule.fields.empty());
    EXPECT_TRUE(rule.fieldsRelation == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling018, TestSize.Level1)
{
    nlohmann::json jsonObj;
    nlohmann::json jsonField;
    jsonField["fieldName"] = "fieldName";
    jsonField["fieldType"] = "fieldType";
    jsonField["value"] = "value";
    jsonObj["eventId"] = 0;
    jsonObj["fields"] = {jsonField, jsonField};
    jsonObj["fieldsRelation"] = "fieldsRelation";
    SecurityGuard::Rule rule = jsonObj.get<SecurityGuard::Rule>();
    EXPECT_TRUE(rule.eventId == 0);
    EXPECT_TRUE(!rule.fields.empty());
    EXPECT_TRUE(rule.fieldsRelation == "fieldsRelation");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling019, TestSize.Level1)
{
    nlohmann::json jsonObj;
    SecurityGuard::BuildInDetectionCfg cfg = jsonObj.get<SecurityGuard::BuildInDetectionCfg>();
    EXPECT_TRUE(cfg.rules.empty());
    EXPECT_TRUE(cfg.rulesRelation == "");
    EXPECT_TRUE(cfg.trueResult == "");
    EXPECT_TRUE(cfg.falseResult == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling020, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["rules"] = 0;
    SecurityGuard::BuildInDetectionCfg cfg = jsonObj.get<SecurityGuard::BuildInDetectionCfg>();
    EXPECT_TRUE(cfg.rules.empty());
    EXPECT_TRUE(cfg.rulesRelation == "");
    EXPECT_TRUE(cfg.trueResult == "");
    EXPECT_TRUE(cfg.falseResult == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling021, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["rules"] = 0;
    jsonObj["rulesRelation"] = 0;
    SecurityGuard::BuildInDetectionCfg cfg = jsonObj.get<SecurityGuard::BuildInDetectionCfg>();
    EXPECT_TRUE(cfg.rules.empty());
    EXPECT_TRUE(cfg.rulesRelation == "");
    EXPECT_TRUE(cfg.trueResult == "");
    EXPECT_TRUE(cfg.falseResult == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling022, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["rules"] = 0;
    jsonObj["rulesRelation"] = 0;
    jsonObj["trueResult"] = 0;
    SecurityGuard::BuildInDetectionCfg cfg = jsonObj.get<SecurityGuard::BuildInDetectionCfg>();
    EXPECT_TRUE(cfg.rules.empty());
    EXPECT_TRUE(cfg.rulesRelation == "");
    EXPECT_TRUE(cfg.trueResult == "");
    EXPECT_TRUE(cfg.falseResult == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling023, TestSize.Level1)
{
    nlohmann::json jsonObj;
    jsonObj["rules"] = 0;
    jsonObj["rulesRelation"] = 0;
    jsonObj["trueResult"] = 0;
    jsonObj["falseResult"] = 0;
    SecurityGuard::BuildInDetectionCfg cfg = jsonObj.get<SecurityGuard::BuildInDetectionCfg>();
    EXPECT_TRUE(cfg.rules.empty());
    EXPECT_TRUE(cfg.rulesRelation == "");
    EXPECT_TRUE(cfg.trueResult == "");
    EXPECT_TRUE(cfg.falseResult == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling024, TestSize.Level1)
{
    nlohmann::json jsonObj;
    nlohmann::json jsonRule;
    nlohmann::json jsonField;
    jsonField["fieldName"] = "fieldName";
    jsonField["fieldType"] = "fieldType";
    jsonField["value"] = "value";
    jsonRule["eventId"] = 0;
    jsonRule["fields"] = {jsonField, jsonField};
    jsonRule["fieldsRelation"] = "fieldsRelation";
    jsonObj["rules"] = {jsonRule, jsonRule};
    jsonObj["rulesRelation"] = 0;
    jsonObj["trueResult"] = 0;
    jsonObj["falseResult"] = 0;
    SecurityGuard::BuildInDetectionCfg cfg = jsonObj.get<SecurityGuard::BuildInDetectionCfg>();
    EXPECT_TRUE(cfg.rules.empty());
    EXPECT_TRUE(cfg.rulesRelation == "");
    EXPECT_TRUE(cfg.trueResult == "");
    EXPECT_TRUE(cfg.falseResult == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling025, TestSize.Level1)
{
    nlohmann::json jsonObj;
    nlohmann::json jsonRule;
    nlohmann::json jsonField;
    jsonField["fieldName"] = "fieldName";
    jsonField["fieldType"] = "fieldType";
    jsonField["value"] = "value";
    jsonRule["eventId"] = 0;
    jsonRule["fields"] = {jsonField, jsonField};
    jsonRule["fieldsRelation"] = "fieldsRelation";
    jsonObj["rules"] = {jsonRule, jsonRule};
    jsonObj["rulesRelation"] = "rulesRelation";
    jsonObj["trueResult"] = 0;
    jsonObj["falseResult"] = 0;
    SecurityGuard::BuildInDetectionCfg cfg = jsonObj.get<SecurityGuard::BuildInDetectionCfg>();
    EXPECT_TRUE(cfg.rules.empty());
    EXPECT_TRUE(cfg.rulesRelation == "");
    EXPECT_TRUE(cfg.trueResult == "");
    EXPECT_TRUE(cfg.falseResult == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling026, TestSize.Level1)
{
    nlohmann::json jsonObj;
    nlohmann::json jsonRule;
    nlohmann::json jsonField;
    jsonField["fieldName"] = "fieldName";
    jsonField["fieldType"] = "fieldType";
    jsonField["value"] = "value";
    jsonRule["eventId"] = 0;
    jsonRule["fields"] = {jsonField, jsonField};
    jsonRule["fieldsRelation"] = "fieldsRelation";
    jsonObj["rules"] = {jsonRule, jsonRule};
    jsonObj["rulesRelation"] = "rulesRelation";
    jsonObj["trueResult"] = "trueResult";
    jsonObj["falseResult"] = 0;
    SecurityGuard::BuildInDetectionCfg cfg = jsonObj.get<SecurityGuard::BuildInDetectionCfg>();
    EXPECT_TRUE(cfg.rules.empty());
    EXPECT_TRUE(cfg.rulesRelation == "");
    EXPECT_TRUE(cfg.trueResult == "");
    EXPECT_TRUE(cfg.falseResult == "");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestModelCfgMarshalling027, TestSize.Level1)
{
    nlohmann::json jsonObj;
    nlohmann::json jsonRule;
    nlohmann::json jsonField;
    jsonField["fieldName"] = "fieldName";
    jsonField["fieldType"] = "fieldType";
    jsonField["value"] = "value";
    jsonRule["eventId"] = 0;
    jsonRule["fields"] = {jsonField, jsonField};
    jsonRule["fieldsRelation"] = "fieldsRelation";
    jsonObj["rules"] = {jsonRule, jsonRule};
    jsonObj["rulesRelation"] = "rulesRelation";
    jsonObj["trueResult"] = "trueResult";
    jsonObj["falseResult"] = "falseResult";
    SecurityGuard::BuildInDetectionCfg cfg = jsonObj.get<SecurityGuard::BuildInDetectionCfg>();
    EXPECT_TRUE(!cfg.rules.empty());
    EXPECT_TRUE(cfg.rulesRelation == "rulesRelation");
    EXPECT_TRUE(cfg.trueResult == "trueResult");
    EXPECT_TRUE(cfg.falseResult == "falseResult");
}

HWTEST_F(SecurityGuardConfigManagerTest, TestUnmarshal001, testing::ext::TestSize.Level1)
{
    using namespace OHOS::Security::SecurityGuard;
    nlohmann::json jsonOb {
        {"version", "xxx"},
        {"releaseTime", "xxx"},
        {"detectMaxRecord", 999},
        {"uidMaxDnsRecord", 10},
        {"detectMaxTime", 86399},
        {"ipBlackList", {"1", "2"}},
        {"ipBlackListMock", {"xxx", "xxx"}},
        {"dnsBlackList", {"1", "2"}},
        {"number", {1, 2}}
    };
    std::vector<std::string> testVec {};
    std::vector<int64_t> testVecInt {};
    std::vector<int32_t> testVecIntS{};
    uint64_t data;
    int64_t dataInt;
    int32_t i32Data;
    uint32_t u32Data;

    EXPECT_TRUE(JsonCfg::Unmarshal(i32Data, jsonOb, "detectMaxRecord"));
    EXPECT_FALSE(JsonCfg::Unmarshal(i32Data, jsonOb, "releaseTime"));
    EXPECT_FALSE(JsonCfg::Unmarshal(i32Data, jsonOb, "isexist"));

    EXPECT_TRUE(JsonCfg::Unmarshal(u32Data, jsonOb, "detectMaxRecord"));
    EXPECT_FALSE(JsonCfg::Unmarshal(u32Data, jsonOb, "releaseTime"));
    EXPECT_FALSE(JsonCfg::Unmarshal(u32Data, jsonOb, "isexist"));

    EXPECT_TRUE(JsonCfg::Unmarshal(data, jsonOb, "detectMaxRecord"));
    EXPECT_FALSE(JsonCfg::Unmarshal(data, jsonOb, "releaseTime"));
    EXPECT_FALSE(JsonCfg::Unmarshal(data, jsonOb, "isexist"));

    EXPECT_TRUE(JsonCfg::Unmarshal(dataInt, jsonOb, "uidMaxDnsRecord"));
    EXPECT_FALSE(JsonCfg::Unmarshal(dataInt, jsonOb, "releaseTime"));
    EXPECT_FALSE(JsonCfg::Unmarshal(dataInt, jsonOb, "isexist"));

    EXPECT_TRUE(JsonCfg::Unmarshal(testVec, jsonOb, "ipBlackList"));
    EXPECT_FALSE(JsonCfg::Unmarshal(testVec, jsonOb, "isexist"));
    EXPECT_FALSE(JsonCfg::Unmarshal(testVec, jsonOb, "number"));

    EXPECT_TRUE(JsonCfg::Unmarshal(testVecInt, jsonOb, "number"));
    EXPECT_FALSE(JsonCfg::Unmarshal(testVecInt, jsonOb, "ipBlackList"));
    EXPECT_FALSE(JsonCfg::Unmarshal(testVecInt, jsonOb, "isexist"));

    EXPECT_TRUE(JsonCfg::Unmarshal(testVecIntS, jsonOb, "number"));
    EXPECT_FALSE(JsonCfg::Unmarshal(testVecIntS, jsonOb, "ipBlackList"));
    EXPECT_FALSE(JsonCfg::Unmarshal(testVecIntS, jsonOb, "isexist"));
}

HWTEST_F(SecurityGuardConfigManagerTest, TestEventGroupConfig001, TestSize.Level1)
{
    EventGroupConfig config;
    bool success = config.Load(INIT_MODE);
    EXPECT_TRUE(success);
    config.Parse();
    EXPECT_FALSE(config.Load(UPDATE_MODE));
    EXPECT_TRUE(config.Update());
}

HWTEST_F(SecurityGuardConfigManagerTest, TestEventGroupConfigFail001, TestSize.Level1)
{
    EventGroupConfig config;
    nlohmann::json jsonObj;
    nlohmann::json jsonGroupInfo;
    EXPECT_FALSE(config.ParseEventGroupConfig(jsonObj));
    jsonObj["eventGroupList"] = "test";
    EXPECT_FALSE(config.ParseEventGroupConfig(jsonObj));
    jsonObj.clear();
    jsonGroupInfo["test"] = "";
    jsonObj["eventGroupList"] = {jsonGroupInfo, jsonGroupInfo};
    EXPECT_FALSE(config.ParseEventGroupConfig(jsonObj));
    jsonGroupInfo.clear();
    jsonObj.clear();
    jsonGroupInfo["eventGroupName"] = "";
    jsonObj["eventGroupList"] = {jsonGroupInfo, jsonGroupInfo};
    EXPECT_FALSE(config.ParseEventGroupConfig(jsonObj));
    jsonGroupInfo.clear();
    jsonObj.clear();
    jsonGroupInfo["eventGroupName"] = "Sec";
    jsonObj["eventGroupList"] = {jsonGroupInfo, jsonGroupInfo};
    EXPECT_FALSE(config.ParseEventGroupConfig(jsonObj));
    jsonGroupInfo.clear();
    jsonObj.clear();
    jsonGroupInfo["eventGroupName"] = "Sec";
    jsonGroupInfo["eventList"] = {"", "1111111111111111111111111111111111111111111111111111111"};
    jsonObj["eventGroupList"] = {jsonGroupInfo, jsonGroupInfo};
    EXPECT_FALSE(config.ParseEventGroupConfig(jsonObj));
    jsonGroupInfo.clear();
    jsonObj.clear();
    jsonGroupInfo["eventGroupName"] = "Sec";
    jsonGroupInfo["eventList"] = {"123", "11111"};
    jsonGroupInfo["permission"] = {"test", "test1"};
    jsonObj["eventGroupList"] = {jsonGroupInfo, jsonGroupInfo};
    EXPECT_FALSE(config.ParseEventGroupConfig(jsonObj));
}

HWTEST_F(SecurityGuardConfigManagerTest, GetEventGroupConfig001, TestSize.Level1)
{
    EventGroupCfg config {};
    EXPECT_FALSE(ConfigDataManager::GetInstance().GetEventGroupConfig("testttt", config));
    ConfigDataManager::GetInstance().eventGroupMap_.insert({"testttt", config});
    EXPECT_TRUE(ConfigDataManager::GetInstance().GetEventGroupConfig("testttt", config));
}

HWTEST_F(SecurityGuardConfigManagerTest, GetIsBatchUpload001, TestSize.Level1)
{
    EXPECT_FALSE(ConfigDataManager::GetInstance().GetIsBatchUpload("test11"));
    EventGroupCfg config {};
    config.isBatchUpload = true;
    ConfigDataManager::GetInstance().eventGroupMap_.insert({"test11", config});
    EXPECT_TRUE(ConfigDataManager::GetInstance().GetIsBatchUpload("test11"));
}

void SecurityGuardUtilsTest::SetUpTestCase()
{
}

void SecurityGuardUtilsTest::TearDownTestCase()
{
}

void SecurityGuardUtilsTest::SetUp()
{
    constexpr int64_t overInt32 = 2147483648;
    rootJson = cJSON_CreateObject();
    cJSON_AddBoolToObject(rootJson, "key1", true);
    cJSON_AddBoolToObject(rootJson, "key2", false);
    cJSON_AddNumberToObject(rootJson, "key3", 0);
    cJSON_AddNumberToObject(rootJson, "key4", 1);
    cJSON_AddNumberToObject(rootJson, "key5", -1);
    cJSON_AddNumberToObject(rootJson, "key6", overInt32);
    cJSON_AddNullToObject(rootJson, "key7");
    cJSON_AddStringToObject(rootJson, "key8", "valid_string");
}

void SecurityGuardUtilsTest::TearDown()
{
    cJSON_Delete(rootJson);
}

HWTEST_F(SecurityGuardUtilsTest, ReadFileToStrReturnFalse001, TestSize.Level1)
{
    std::string fileName = "non_existent_file.txt";
    std::ios::pos_type fileMaxSize = 1024;
    std::string str;

    EXPECT_FALSE(ReadFileToStr(fileName, fileMaxSize, str));
}

HWTEST_F(SecurityGuardUtilsTest, ReadFileToStrReturnFalse002, TestSize.Level1)
{
    std::string fileName = "empty_file.txt";
    std::ios::pos_type fileMaxSize = 1024;
    std::string str;
    std::ofstream emptyFile(fileName);
    emptyFile.close();
    EXPECT_FALSE(ReadFileToStr(fileName, fileMaxSize, str));
    std::remove(fileName.c_str());
}

HWTEST_F(SecurityGuardUtilsTest, ReadFileToStrReturnFalse003, TestSize.Level1)
{
    std::string fileName = "large_file.txt";
    std::ios::pos_type fileMaxSize = 10;
    std::string str;
    std::ofstream largeFile(fileName);

    largeFile << "aaaaaaaaaaaaaaaaaaaa";
    largeFile.close();

    EXPECT_FALSE(ReadFileToStr(fileName, fileMaxSize, str));
    std::remove(fileName.c_str());
}

HWTEST_F(SecurityGuardUtilsTest, ReadFileToStrReturnTrue001, TestSize.Level1)
{
    std::string fileName = "valid_file.txt";
    std::ios::pos_type fileMaxSize = 1024;
    std::string str;

    std::ofstream validFile(fileName);
    validFile << "hello, world!";
    validFile.close();

    EXPECT_TRUE(ReadFileToStr(fileName, fileMaxSize, str));
    EXPECT_EQ(str, "hello, world!");

    std::remove(fileName.c_str());
}

HWTEST_F(SecurityGuardUtilsTest, GetBoolTestTrue, TestSize.Level1)
{
    bool result;
    bool success = GetBool(rootJson, "key1", result);
    EXPECT_TRUE(success);
    EXPECT_TRUE(result);
}

HWTEST_F(SecurityGuardUtilsTest, GetBoolTestFalse001, TestSize.Level1)
{
    bool result;
    bool success = GetBool(rootJson, "key2", result);
    EXPECT_TRUE(success);
    EXPECT_FALSE(result);
}

HWTEST_F(SecurityGuardUtilsTest, GetBoolTestFalse002, TestSize.Level1)
{
    bool result;
    bool success = GetBool(rootJson, "key_error", result);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardUtilsTest, GetBoolTestFalse003, TestSize.Level1)
{
    bool result;
    bool success = GetBool(rootJson, "key3", result);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardUtilsTest, GetBoolTestFalse004, TestSize.Level1)
{
    bool result;
    bool success = GetBool(nullptr, "key1", result);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardUtilsTest, TestValidFailed001, TestSize.Level1)
{
    int64_t result;
    bool success = GetNumberInt64(nullptr, "key3", result);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardUtilsTest, TestValidFailed002, TestSize.Level1)
{
    int64_t result;
    bool success = GetNumberInt64(rootJson, "key_error", result);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardUtilsTest, TestValidFailed003, TestSize.Level1)
{
    int64_t result;
    bool success = GetNumberInt64(rootJson, "key1", result);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardUtilsTest, TestValidZero002, TestSize.Level1)
{
    int64_t result;
    bool success = GetNumberInt64(rootJson, "key3", result);
    EXPECT_TRUE(success);
    EXPECT_EQ(result, 0);
}

HWTEST_F(SecurityGuardUtilsTest, TestValidPositive002, TestSize.Level1)
{
    int64_t result;
    bool success = GetNumberInt64(rootJson, "key4", result);
    EXPECT_TRUE(success);
    EXPECT_EQ(result, 1);
}

HWTEST_F(SecurityGuardUtilsTest, TestValidNegative002, TestSize.Level1)
{
    int64_t result;
    bool success = GetNumberInt64(rootJson, "key5", result);
    EXPECT_TRUE(success);
    EXPECT_EQ(result, -1);
}

HWTEST_F(SecurityGuardUtilsTest, TestValidFailed011, TestSize.Level1)
{
    int32_t result;
    bool success = GetNumberInt32(nullptr, "key3", result);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardUtilsTest, TestValidFailed012, TestSize.Level1)
{
    int32_t result;
    bool success = GetNumberInt32(rootJson, "key_error", result);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardUtilsTest, TestValidFailed013, TestSize.Level1)
{
    int32_t result;
    bool success = GetNumberInt32(rootJson, "key1", result);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardUtilsTest, TestValidZero001, TestSize.Level1)
{
    int32_t result;
    bool success = GetNumberInt32(rootJson, "key3", result);
    EXPECT_TRUE(success);
    EXPECT_EQ(result, 0);
}

HWTEST_F(SecurityGuardUtilsTest, TestValidPositive001, TestSize.Level1)
{
    int32_t result;
    bool success = GetNumberInt32(rootJson, "key4", result);
    EXPECT_TRUE(success);
    EXPECT_EQ(result, 1);
}

HWTEST_F(SecurityGuardUtilsTest, TestValidNegative001, TestSize.Level1)
{
    int32_t result;
    bool success = GetNumberInt32(rootJson, "key5", result);
    EXPECT_TRUE(success);
    EXPECT_EQ(result, -1);
}

HWTEST_F(SecurityGuardUtilsTest, TestValidOverMaxInt32, TestSize.Level1)
{
    int32_t result;
    bool success = GetNumberInt32(rootJson, "key6", result);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardUtilsTest, TestValidFailed021, TestSize.Level1)
{
    std::string result;
    bool success = GetString(nullptr, "key3", result);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardUtilsTest, TestValidFailed022, TestSize.Level1)
{
    std::string result;
    bool success = GetString(rootJson, "key_error", result);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardUtilsTest, TestValidFailed023, TestSize.Level1)
{
    std::string result;
    bool success = GetString(rootJson, "key7", result);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardUtilsTest, TestValidSuccess020, TestSize.Level1)
{
    std::string result;
    bool success = GetString(rootJson, "key8", result);
    EXPECT_TRUE(success);
}

HWTEST_F(SecurityGuardUtilsTest, TestGetStringNoKeyFail001, TestSize.Level1)
{
    std::string result;
    bool success = GetStringNoKey(nullptr, result);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardUtilsTest, TestAddString, TestSize.Level1)
{
    std::string key = "testKey";
    std::string value = "testValue";
    bool success = AddString(rootJson, key, value);
    EXPECT_TRUE(success);

    cJSON *item = cJSON_GetObjectItem(rootJson, key.c_str());
    EXPECT_TRUE(item != nullptr);
    EXPECT_TRUE(cJSON_IsString(item));
    EXPECT_STREQ(cJSON_GetStringValue(item), value.c_str());
}

HWTEST_F(SecurityGuardUtilsTest, TestAddNumberInt32, TestSize.Level1)
{
    std::string key = "testKey";
    int32_t value = 12345;
    bool success = AddNumberInt32(rootJson, key, value);
    EXPECT_TRUE(success);

    cJSON *item = cJSON_GetObjectItem(rootJson, key.c_str());
    EXPECT_TRUE(item != nullptr);
    EXPECT_TRUE(cJSON_IsNumber(item));
    EXPECT_EQ(cJSON_GetNumberValue(item), value);
}

HWTEST_F(SecurityGuardUtilsTest, TestAddNumberInt64, TestSize.Level1)
{
    std::string key = "testKey";
    int64_t value = 123456789012345LL;
    bool success = AddNumberInt64(rootJson, key, value);
    EXPECT_TRUE(success);

    cJSON *item = cJSON_GetObjectItem(rootJson, key.c_str());
    EXPECT_TRUE(item != nullptr);
    EXPECT_TRUE(cJSON_IsNumber(item));
    EXPECT_EQ(cJSON_GetNumberValue(item), value);
}

HWTEST_F(SecurityGuardUtilsTest, TestAddStrArrayInfo, TestSize.Level1)
{
    std::vector<std::string> values = {"item1", "item2", "item3"};
    const char *key = "testArrayKey";
    bool success = AddStrArrayInfo(rootJson, values, key);
    EXPECT_TRUE(success);

    cJSON *array = cJSON_GetObjectItem(rootJson, key);
    EXPECT_TRUE(array != nullptr);
    EXPECT_TRUE(cJSON_IsArray(array));
    EXPECT_EQ(cJSON_GetArraySize(array), values.size());

    for (size_t i = 0; i < values.size(); i++) {
        cJSON *item = cJSON_GetArrayItem(array, i);
        EXPECT_TRUE(item != nullptr);
        EXPECT_TRUE(cJSON_IsString(item));
        EXPECT_STREQ(cJSON_GetStringValue(item), values[i].c_str());
    }
}

HWTEST_F(SecurityGuardUtilsTest, TestAddStringNullJson, TestSize.Level1)
{
    std::string key = "testKey";
    std::string value = "testValue";
    bool success = AddString(nullptr, key, value);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardUtilsTest, TestAddNumberInt32NullJson, TestSize.Level1)
{
    std::string key = "testKey";
    int32_t value = 12345;
    bool success = AddNumberInt32(nullptr, key, value);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardUtilsTest, TestAddNumberInt64NullJson, TestSize.Level1)
{
    std::string key = "testKey";
    int64_t value = 123456789012345LL;
    bool success = AddNumberInt64(nullptr, key, value);
    EXPECT_FALSE(success);
}

HWTEST_F(SecurityGuardUtilsTest, TestAddStrArrayInfoNullJson, TestSize.Level1)
{
    std::vector<std::string> values = {"item1", "item2", "item3"};
    const char *key = "testArrayKey";
    bool success = AddStrArrayInfo(nullptr, values, key);
    EXPECT_FALSE(success);
}

// Covers ConfigSubscriber::GetUpdateFileDstPath:
// 001: file missing or fileName not matched, dstPath keeps its original value.
HWTEST_F(SecurityGuardConfigManagerTest, GetUpdateFileDstPath001, TestSize.Level1)
{
    std::string dstPath = "origin";
    ConfigSubscriber::GetUpdateFileDstPath("no_such_update_file_name", dstPath);
    EXPECT_EQ(dstPath, "origin");
}

// 002: bootstrap the first valid {fileName, dstPath} entry from the real update
// config file (if deployed) and verify the match branch assigns dstPath.
HWTEST_F(SecurityGuardConfigManagerTest, GetUpdateFileDstPath002, TestSize.Level1)
{
    const std::string updateCfgFile = "/system/etc/security_guard_update_config.json";
    std::string jsonStr;
    if (!FileUtil::ReadFileToStr(updateCfgFile, 1 * 1024 * 1024, jsonStr)) {
        GTEST_LOG_(WARNING) << "update config file not present, skip match branch";
        return;
    }
    cJSON *root = cJSON_Parse(jsonStr.c_str());
    if (root == nullptr || !cJSON_IsArray(root)) {
        cJSON_Delete(root);
        return;
    }
    std::string fileName;
    std::string expectDst;
    bool found = false;
    int size = cJSON_GetArraySize(root);
    for (int i = 0; i < size && !found; i++) {
        cJSON *item = cJSON_GetArrayItem(root, i);
        if (JsonUtil::GetString(item, "fileName", fileName) && JsonUtil::GetString(item, "dstPath", expectDst)) {
            found = true;
        }
    }
    cJSON_Delete(root);
    if (!found) {
        GTEST_LOG_(WARNING) << "no valid {fileName, dstPath} entry, skip match branch";
        return;
    }
    std::string dstPath;
    ConfigSubscriber::GetUpdateFileDstPath(fileName, dstPath);
    EXPECT_EQ(dstPath, expectDst);
}

// Covers ConfigSubscriber::UpdateConfig (config_subscriber.cpp:83-89):
// 001: empty file, dstPath stays empty and CopyFile is skipped.
HWTEST_F(SecurityGuardConfigManagerTest, UpdateConfig001, TestSize.Level1)
{
    bool ret = ConfigSubscriber::UpdateConfig("");
    EXPECT_FALSE(ret);
}

// 002: non-cache existing file, no matching update entry: dstPath keeps the
// file value, CopyFile(file, file) succeeds via tmp+rename, config update
// event is reported and the tmp file is removed by UpdateConfig itself.
HWTEST_F(SecurityGuardConfigManagerTest, UpdateConfig002, TestSize.Level1)
{
    const std::string file = "/data/local/tmp/sg_update_config_test.json";
    {
        std::ofstream out(file);
        out << "update config test content";
    }
    bool ret = ConfigSubscriber::UpdateConfig(file);
    EXPECT_TRUE(ret);
    EXPECT_EQ(access(file.c_str(), F_OK), -1); // removed by UpdateConfig
}

// Covers SwapEventConfigMapWithTables: eventMap_ swapped and eventToTableMap_ upserted
// in one atomic commit; stale table entries are kept (upsert semantics).
HWTEST_F(SecurityGuardConfigManagerTest, TestConfigDataManager004, TestSize.Level1)
{
    ConfigDataManager::GetInstance().ResetEventMap();
    ConfigDataManager::GetInstance().ResetEventToTableMap();
    EventCfg oldCfg {};
    oldCfg.eventId = 9001;
    ConfigDataManager::GetInstance().InsertEventMap(9001, oldCfg);
    ConfigDataManager::GetInstance().InsertEventToTableMap(9001, "old_table");

    EventCfg newCfg {};
    newCfg.eventId = 9002;
    std::unordered_map<int64_t, EventCfg> newEventMap {};
    newEventMap[9002] = newCfg;
    std::vector<std::pair<int64_t, std::string>> eventToTables {};
    eventToTables.emplace_back(9002, "new_table");
    ConfigDataManager::GetInstance().SwapEventConfigMapWithTables(std::move(newEventMap), eventToTables);

    EventCfg outCfg {};
    EXPECT_FALSE(ConfigDataManager::GetInstance().GetEventConfig(9001, outCfg)); // 旧代换出
    EXPECT_TRUE(ConfigDataManager::GetInstance().GetEventConfig(9002, outCfg)); // 新代换入
    EXPECT_EQ(ConfigDataManager::GetInstance().GetTableFromEventId(9002), "new_table"); // 新表映射同时生效
    EXPECT_EQ(ConfigDataManager::GetInstance().GetTableFromEventId(9001), "old_table"); // 旧表条目保留
    ConfigDataManager::GetInstance().ResetEventMap();
    ConfigDataManager::GetInstance().ResetEventToTableMap();
}

// 写入 EventConfig::Update 的输入流内容（含 oldEventId 别名与 db_table 表映射）
static void WriteAtomicUpdateCfg(const std::string &file)
{
    std::ofstream out(file);
    out << R"({
    "eventcfg": [
        {
        "eventId" : "0000000009",
        "oldEventId" : "0000000008",
        "eventName" : "ut_atomic_event",
        "version" : 0,
        "eventType" : 0,
        "dataSensitivityLevel" : 0,
        "storageRamNums" : 1,
        "storageRomNums" : 5,
        "storageTime" : -1,
        "owner":["3001000000"],
        "source":0,
        "isBatchUpload" : 0,
        "db_table" : "ut_risk_table"
        }
    ]
})";
}

// 兜底重建 Update 依赖的 cache 源（内容与部署资源一致，覆盖后跨轮行为不变），返回是否写入成功
static bool RewriteCacheEventCfg()
{
    std::ofstream cacheOut(CONFIG_CACHE_FILES[EVENT_CFG_INDEX], std::ios::trunc);
    cacheOut << R"({
    "eventcfg": [
        {
        "eventId" : "0000000001",
        "eventName" : "cache_event",
        "version" : 0,
        "eventType" : 0,
        "dataSensitivityLevel" : 0,
        "storageRamNums" : 1,
        "storageRomNums" : 5,
        "storageTime" : -1,
        "owner":["3001000000"],
        "source":0,
        "isBatchUpload" : 0
        }
    ]
})";
    return !cacheOut.fail();
}

// Covers EventConfig::Update atomic commit: after update, every event of the new
// config (including the oldEventId alias) is visible in eventMap_ with its table
// mapping at the same time, no window of "new event without table".
HWTEST_F(SecurityGuardConfigManagerTest, TestEventConfigUpdateTableAtomic001, TestSize.Level1)
{
    // 与其他用例同目录，规避 /data/local/tmp 在部分板子上的写权限差异
    const std::string file = "/data/test/unittest/resource/ut_event_config_update_atomic.cfg";
    WriteAtomicUpdateCfg(file);
    EXPECT_EQ(access(file.c_str(), F_OK), 0);
    // 资源未部署/不可读时兜底，保证 CopyFile 分支可走通
    EXPECT_TRUE(RewriteCacheEventCfg());
    ConfigDataManager::GetInstance().ResetEventMap();
    ConfigDataManager::GetInstance().ResetEventToTableMap();
    EventConfig config;
    config.stream_.open(file);
    EXPECT_TRUE(config.stream_.is_open());
    EXPECT_TRUE(config.Update());
    EventCfg outCfg {};
    EXPECT_TRUE(ConfigDataManager::GetInstance().GetEventConfig(9, outCfg));
    EXPECT_EQ(ConfigDataManager::GetInstance().GetTableFromEventId(9), "ut_risk_table");
    EXPECT_TRUE(ConfigDataManager::GetInstance().GetEventConfig(8, outCfg)); // oldEventId 别名同代可见
    EXPECT_EQ(ConfigDataManager::GetInstance().GetTableFromEventId(8), "ut_risk_table");
    ConfigDataManager::GetInstance().ResetEventMap();
    ConfigDataManager::GetInstance().ResetEventToTableMap();
    unlink(file.c_str());
}
}
