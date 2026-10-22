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

#include "data_collect_kit_test.h"

#include "file_ex.h"
#include "nativetoken_kit.h"
#include "securec.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"
#include "sg_obtaindata_client.h"
#define private public
#include "event_subscribe_client.h"
#include "data_collect_manager.h"
#include "security_guard_define.h"
#include "sg_collect_client.h"
#undef private

#define private public
#include "iservice_registry.h"
#undef private

using namespace testing::ext;
using namespace OHOS::Security::SecurityGuardTest;

#ifdef __cplusplus
extern "C" {
#endif
    int32_t ReportSecurityInfo(const struct EventInfoSt *info);
    int32_t ReportSecurityInfoAsync(const struct EventInfoSt *info);
#ifdef __cplusplus
}
#endif

namespace OHOS::Security::SecurityGuardTest {

// ISystemAbilityManager mock: GetSystemAbility always returns nullptr, so
// iface_cast gets a null object and the "proxy is null" branches are reachable.
class NullSystemAbilityManager : public OHOS::ISystemAbilityManager {
public:
    NullSystemAbilityManager() = default;
    ~NullSystemAbilityManager() override = default;
    OHOS::sptr<OHOS::IRemoteObject> AsObject() override { return nullptr; }
    std::vector<std::u16string> ListSystemAbilities(unsigned int dumpFlags) override { return {}; }
    OHOS::sptr<OHOS::IRemoteObject> GetSystemAbility(int32_t systemAbilityId) override { return nullptr; }
    OHOS::sptr<OHOS::IRemoteObject> CheckSystemAbility(int32_t systemAbilityId) override { return {}; }
    int32_t RemoveSystemAbility(int32_t systemAbilityId) override { return {}; }
    int32_t SubscribeSystemAbility(int32_t systemAbilityId,
        const OHOS::sptr<OHOS::ISystemAbilityStatusChange>& listener) override { return {}; }
    int32_t UnSubscribeSystemAbility(int32_t systemAbilityId,
        const OHOS::sptr<OHOS::ISystemAbilityStatusChange>& listener) override { return {}; }
    OHOS::sptr<OHOS::IRemoteObject> GetSystemAbility(int32_t systemAbilityId,
        const std::string& deviceId) override { return {}; }
    OHOS::sptr<OHOS::IRemoteObject> CheckSystemAbility(int32_t systemAbilityId,
        const std::string& deviceId) override { return {}; }
    int32_t AddOnDemandSystemAbilityInfo(int32_t systemAbilityId,
        const std::u16string& localAbilityManagerName) override { return {}; }
    OHOS::sptr<OHOS::IRemoteObject> CheckSystemAbility(int32_t systemAbilityId, bool& isExist) override { return {}; }
    int32_t AddSystemAbility(int32_t systemAbilityId, const OHOS::sptr<OHOS::IRemoteObject>& ability,
        const SAExtraProp& extraProp) override { return {}; }
    int32_t AddSystemProcess(const std::u16string& procName,
        const OHOS::sptr<OHOS::IRemoteObject>& procObject) override { return {}; }
    OHOS::sptr<OHOS::IRemoteObject> LoadSystemAbility(int32_t systemAbilityId, int32_t timeout) override { return {}; }
    int32_t LoadSystemAbility(int32_t systemAbilityId,
        const OHOS::sptr<OHOS::ISystemAbilityLoadCallback>& callback) override { return {}; }
    int32_t LoadSystemAbility(int32_t systemAbilityId, const std::string& deviceId,
        const OHOS::sptr<OHOS::ISystemAbilityLoadCallback>& callback) override { return {}; }
    int32_t UnloadSystemAbility(int32_t systemAbilityId) override { return {}; }
    int32_t CancelUnloadSystemAbility(int32_t systemAbilityId) override { return {}; }
    int32_t UnloadAllIdleSystemAbility() override { return {}; }
    int32_t GetSystemProcessInfo(int32_t systemAbilityId,
        OHOS::SystemProcessInfo& systemProcessInfo) override { return {}; }
    int32_t GetRunningSystemProcess(std::list<OHOS::SystemProcessInfo>& systemProcessInfos) override { return {}; }
    int32_t SubscribeSystemProcess(const OHOS::sptr<OHOS::ISystemProcessStatusChange>& listener) override
    {
        return {};
    }
    int32_t SendStrategy(int32_t type, std::vector<int32_t>& systemAbilityIds, int32_t level,
        std::string& action) override { return {}; }
    int32_t UnSubscribeSystemProcess(const OHOS::sptr<OHOS::ISystemProcessStatusChange>& listener) override
    {
        return {};
    }
    int32_t GetExtensionSaIds(const std::string& extension, std::vector<int32_t> &saIds) override { return {}; }
    int32_t GetExtensionRunningSaList(const std::string& extension,
        std::vector<OHOS::sptr<OHOS::IRemoteObject>>& saList) override { return {}; }
    int32_t GetRunningSaExtensionInfoList(const std::string& extension,
        std::vector<SaExtensionInfo>& infoList) override { return {}; }
    int32_t GetCommonEventExtraDataIdlist(int32_t saId, std::vector<int64_t>& extraDataIdList,
        const std::string& eventName) override { return {}; }
    int32_t GetOnDemandReasonExtraData(int64_t extraDataId,
        OHOS::MessageParcel& extraDataParcel) override { return {}; }
    int32_t GetOnDemandPolicy(int32_t systemAbilityId, OnDemandPolicyType type,
        std::vector<SystemAbilityOnDemandEvent>& abilityOnDemandEvents) override { return {}; }
    int32_t UpdateOnDemandPolicy(int32_t systemAbilityId, OnDemandPolicyType type,
        const std::vector<SystemAbilityOnDemandEvent>& abilityOnDemandEvents) override { return {}; }
    int32_t GetOnDemandSystemAbilityIds(std::vector<int32_t>& systemAbilityIds) override { return {}; }
};

// Replace and restore SystemAbilityManagerClient::systemAbilityManager_ (RAII).
class SamgrMockGuard {
public:
    explicit SamgrMockGuard(const OHOS::sptr<OHOS::ISystemAbilityManager> &mock)
    {
        auto &client = OHOS::SystemAbilityManagerClient::GetInstance();
        origin_ = client.systemAbilityManager_;
        client.systemAbilityManager_ = mock;
    }
    ~SamgrMockGuard()
    {
        OHOS::SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = origin_;
    }
private:
    OHOS::sptr<OHOS::ISystemAbilityManager> origin_ {};
};

void DataCollectKitTest::SetUpTestCase()
{
    string isEnforcing;
    LoadStringFromFile("/sys/fs/selinux/enforce", isEnforcing);
    if (isEnforcing.compare("1") == 0) {
        DataCollectKitTest::isEnforcing_ = true;
        SaveStringToFile("/sys/fs/selinux/enforce", "0");
    }
}

void DataCollectKitTest::TearDownTestCase()
{
    if (DataCollectKitTest::isEnforcing_) {
        SaveStringToFile("/sys/fs/selinux/enforce", "1");
    }
}

void DataCollectKitTest::SetUp()
{
}

void DataCollectKitTest::TearDown()
{
}

bool DataCollectKitTest::isEnforcing_ = false;
void DataCollectKitTest::RequestSecurityEventInfoCallBackFunc(const DeviceIdentify *devId, const char *eventBuffList,
    uint32_t status)
{
    EXPECT_TRUE(devId != nullptr);
    EXPECT_TRUE(eventBuffList != nullptr);
}
/**
 * @tc.name: ReportSecurityInfo001
 * @tc.desc: ReportSecurityInfo with right param
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(DataCollectKitTest, ReportSecurityInfo001, TestSize.Level1)
{
    static int64_t eventId = 1011009000;
    static std::string version = "0";
    static std::string content = "{\"cred\":0,\"extra\":\"\",\"status\":0}";
    EventInfoSt info;
    info.eventId = eventId;
    info.version = version.c_str();
    (void) memset_s(info.content, CONTENT_MAX_LEN, 0, CONTENT_MAX_LEN);
    errno_t rc = memcpy_s(info.content, CONTENT_MAX_LEN, content.c_str(), content.length());
    EXPECT_TRUE(rc == EOK);
    info.contentLen = static_cast<uint32_t>(content.length());
    int ret = ReportSecurityInfo(&info);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

/**
 * @tc.name: ReportSecurityInfo002
 * @tc.desc: ReportSecurityInfo with wrong cred
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(DataCollectKitTest, ReportSecurityInfo002, TestSize.Level1)
{
    static int64_t eventId = 1011009000;
    static std::string version = "0";
    static std::string content = "{\"cred\":\"0\",\"extra\":\"\",\"status\":0}";
    EventInfoSt info;
    info.eventId = eventId;
    info.version = version.c_str();
    (void) memset_s(info.content, CONTENT_MAX_LEN, 0, CONTENT_MAX_LEN);
    errno_t rc = memcpy_s(info.content, CONTENT_MAX_LEN, content.c_str(), content.length());
    EXPECT_TRUE(rc == EOK);
    info.contentLen = static_cast<uint32_t>(content.length());
    int ret = ReportSecurityInfo(&info);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

/**
 * @tc.name: ReportSecurityInfo003
 * @tc.desc: ReportSecurityInfo with wrong extra
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(DataCollectKitTest, ReportSecurityInfo003, TestSize.Level1)
{
    static int64_t eventId = 1011009000;
    static std::string version = "0";
    static std::string content = "{\"cred\":0,\"extra\":0,\"status\":0}";
    EventInfoSt info;
    info.eventId = eventId;
    info.version = version.c_str();
    (void) memset_s(info.content, CONTENT_MAX_LEN, 0, CONTENT_MAX_LEN);
    errno_t rc = memcpy_s(info.content, CONTENT_MAX_LEN, content.c_str(), content.length());
    EXPECT_TRUE(rc == EOK);
    info.contentLen = static_cast<uint32_t>(content.length());
    int ret = ReportSecurityInfo(&info);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

/**
 * @tc.name: ReportSecurityInfo004
 * @tc.desc: ReportSecurityInfo with wrong status
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(DataCollectKitTest, ReportSecurityInfo004, TestSize.Level1)
{
    static int64_t eventId = 1011009000;
    static std::string version = "0";
    static std::string content = "{\"cred\":0,\"extra\":\"\",\"status\":\"0\"}";
    EventInfoSt info;
    info.eventId = eventId;
    info.version = version.c_str();
    (void) memset_s(info.content, CONTENT_MAX_LEN, 0, CONTENT_MAX_LEN);
    errno_t rc = memcpy_s(info.content, CONTENT_MAX_LEN, content.c_str(), content.length());
    EXPECT_TRUE(rc == EOK);
    info.contentLen = static_cast<uint32_t>(content.length());
    int ret = ReportSecurityInfo(&info);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

/**
 * @tc.name: ReportSecurityInfo005
 * @tc.desc: ReportSecurityInfo with wrong eventId
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(DataCollectKitTest, ReportSecurityInfo005, TestSize.Level1)
{
    static int64_t eventId = 0;
    static std::string version = "0";
    static std::string content = "{\"cred\":0,\"extra\":\"\",\"status\":0}";
    EventInfoSt info;
    info.eventId = eventId;
    info.version = version.c_str();
    (void) memset_s(info.content, CONTENT_MAX_LEN, 0, CONTENT_MAX_LEN);
    errno_t rc = memcpy_s(info.content, CONTENT_MAX_LEN, content.c_str(), content.length());
    EXPECT_TRUE(rc == EOK);
    info.contentLen = static_cast<uint32_t>(content.length());
    int ret = ReportSecurityInfo(&info);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

/**
 * @tc.name: ReportSecurityInfo006
 * @tc.desc: ReportSecurityInfo with null info
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(DataCollectKitTest, ReportSecurityInfo006, TestSize.Level1)
{
    int ret = ReportSecurityInfo(nullptr);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);
}

/**
 * @tc.name: ReportSecurityInfoAsync001
 * @tc.desc: ReportSecurityInfoAsync with right param
 * @tc.type: FUNC
 * @tc.require: SR000H96L5
 */
HWTEST_F(DataCollectKitTest, ReportSecurityInfoAsync001, TestSize.Level1)
{
    static int64_t eventId = 1011009000;
    static std::string version = "0";
    static std::string content = "{\"cred\":0,\"extra\":\"\",\"status\":0}";
    EventInfoSt info;
    info.eventId = eventId;
    info.version = version.c_str();
    (void) memset_s(info.content, CONTENT_MAX_LEN, 0, CONTENT_MAX_LEN);
    errno_t rc = memcpy_s(info.content, CONTENT_MAX_LEN, content.c_str(), content.length());
    EXPECT_TRUE(rc == EOK);
    info.contentLen = static_cast<uint32_t>(content.length());
    int ret = ReportSecurityInfoAsync(&info);
    EXPECT_EQ(ret, SecurityGuard::SUCCESS);
}

HWTEST_F(DataCollectKitTest, ConfigUpdate001, TestSize.Level1)
{
    EXPECT_NE(SecurityGuardConfigUpdate(-1, "test"), SecurityGuard::SUCCESS);
}

/**
 * @tc.name: Subscribe001
 * @tc.desc: AcquireDataManager Subscribe
 * @tc.type: FUNC
 * @tc.require: AR000IENKB
 */
class MockSubscriberPtr : public SecurityCollector::ICollectorSubscriber {
public:
    explicit MockSubscriberPtr(const SecurityCollector::Event &event) : ICollectorSubscriber(
        event, -1, false, "securityGroup") {};
    ~MockSubscriberPtr() override = default;
    int32_t OnNotify(const SecurityCollector::Event &event) override {return 0;};
};

HWTEST_F(DataCollectKitTest, Subscribe001, TestSize.Level1)
{
    int ret = SecurityGuard::DataCollectManager::GetInstance().Subscribe(nullptr);
    EXPECT_EQ(ret, SecurityGuard::NULL_OBJECT);
}

SecurityCollector::Event g_event {};
auto g_sub = std::make_shared<MockSubscriberPtr>(g_event);

HWTEST_F(DataCollectKitTest, Subscribe002, TestSize.Level1)
{
    SecurityGuard::DataCollectManager::GetInstance().subscribers_.insert(g_sub);
    int ret = SecurityGuard::DataCollectManager::GetInstance().Subscribe(g_sub);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);
    auto sub = std::make_shared<MockSubscriberPtr>(g_event);
    ret = SecurityGuard::DataCollectManager::GetInstance().Subscribe(sub);
    EXPECT_EQ(ret, SecurityGuard::SUCCESS);
    SecurityGuard::DataCollectManager::GetInstance().callback_->OnNotify({g_event});
    SecurityGuard::DataCollectManager::GetInstance().subscribers_.clear();
    ret = SecurityGuard::DataCollectManager::GetInstance().Subscribe(g_sub);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);
}

/**
 * @tc.name: Unsubscribe001
 * @tc.desc: AcquireDataManager Unsubscribe
 * @tc.type: FUNC
 * @tc.require: AR000IENKB
 */
HWTEST_F(DataCollectKitTest, Unsubscribe001, TestSize.Level1)
{
    int ret = SecurityGuard::DataCollectManager::GetInstance().Unsubscribe(nullptr);
    SecurityGuard::DataCollectManager::DeathRecipient recipient = SecurityGuard::DataCollectManager::DeathRecipient();
    recipient.OnRemoteDied(nullptr);
    EXPECT_EQ(ret, SecurityGuard::NULL_OBJECT);
}

HWTEST_F(DataCollectKitTest, Unsubscribe002, TestSize.Level1)
{
    int ret = SecurityGuard::DataCollectManager::GetInstance().Unsubscribe(g_sub);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);
    SecurityGuard::DataCollectManager::GetInstance().subscribers_.insert(g_sub);
    ret = SecurityGuard::DataCollectManager::GetInstance().Unsubscribe(g_sub);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);
    auto sub = std::make_shared<MockSubscriberPtr>(g_event);
    SecurityGuard::DataCollectManager::GetInstance().subscribers_.insert(sub);
    ret = SecurityGuard::DataCollectManager::GetInstance().Unsubscribe(g_sub);
    EXPECT_EQ(ret, SecurityGuard::SUCCESS);
    EXPECT_EQ(SecurityGuard::DataCollectManager::GetInstance().subscribers_.count(g_sub), 0);
}
/**
 * @tc.name: RequestSecurityEventInfoAsync001
 * @tc.desc: RequestSecurityEventInfoAsync with right param
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(DataCollectKitTest, RequestSecurityEventInfoAsync001, TestSize.Level1)
{
    DeviceIdentify deviceIdentify = {};
    static std::string eventList = "{\"eventId\":[1011009000]}";
    int ret = RequestSecurityEventInfoAsync(&deviceIdentify, eventList.c_str(), RequestSecurityEventInfoCallBackFunc);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

/**
 * @tc.name: RequestSecurityEventInfoAsync002
 * @tc.desc: RequestSecurityEventInfoAsync with right param, get all info
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(DataCollectKitTest, RequestSecurityEventInfoAsync002, TestSize.Level1)
{
    DeviceIdentify deviceIdentify = {};
    static std::string eventList = "{\"eventId\":[-1]}";
    int ret = RequestSecurityEventInfoAsync(&deviceIdentify, eventList.c_str(), RequestSecurityEventInfoCallBackFunc);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

/**
 * @tc.name: RequestSecurityEventInfoAsync003
 * @tc.desc: RequestSecurityEventInfoAsync with wrong eventList key
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(DataCollectKitTest, RequestSecurityEventInfoAsync003, TestSize.Level1)
{
    DeviceIdentify deviceIdentify = {};
    static std::string eventList = "{\"eventIds\":[1011009000]}";
    int ret = RequestSecurityEventInfoAsync(&deviceIdentify, eventList.c_str(), RequestSecurityEventInfoCallBackFunc);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

/**
 * @tc.name: RequestSecurityEventInfoAsync004
 * @tc.desc: RequestSecurityEventInfoAsync with wrong eventList content
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(DataCollectKitTest, RequestSecurityEventInfoAsync004, TestSize.Level1)
{
    DeviceIdentify deviceIdentify = {};
    static std::string eventList = "{eventId:[1011009000]}";
    int ret = RequestSecurityEventInfoAsync(&deviceIdentify, eventList.c_str(), RequestSecurityEventInfoCallBackFunc);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

/**
 * @tc.name: RequestSecurityEventInfoAsync005
 * @tc.desc: RequestSecurityEventInfoAsync with wrong eventList null
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(DataCollectKitTest, RequestSecurityEventInfoAsync005, TestSize.Level1)
{
    DeviceIdentify deviceIdentify = {};
    static std::string eventList = "{\"eventIds\":[]}";
    int ret = RequestSecurityEventInfoAsync(&deviceIdentify, eventList.c_str(), RequestSecurityEventInfoCallBackFunc);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

/**
 * @tc.name: RequestSecurityEventInfoAsync006
 * @tc.desc: RequestSecurityEventInfoAsync with wrong eventList not contain right eventId
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(DataCollectKitTest, RequestSecurityEventInfoAsync006, TestSize.Level1)
{
    DeviceIdentify deviceIdentify = {};
    static std::string eventList = "{\"eventIds\":[0]}";
    int ret = RequestSecurityEventInfoAsync(&deviceIdentify, eventList.c_str(), RequestSecurityEventInfoCallBackFunc);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

/**
 * @tc.name: RequestSecurityEventInfoAsync007
 * @tc.desc: RequestSecurityEventInfoAsync with null devId
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(DataCollectKitTest, RequestSecurityEventInfoAsync007, TestSize.Level1)
{
    static std::string eventList = "{\"eventIds\":[0]}";
    int ret = RequestSecurityEventInfoAsync(nullptr, eventList.c_str(), RequestSecurityEventInfoCallBackFunc);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);
}

/**
 * @tc.name: RequestSecurityEventInfoAsync008
 * @tc.desc: RequestSecurityEventInfoAsync with null eventList
 * @tc.type: FUNC
 * @tc.require: SR000H96FD
 */
HWTEST_F(DataCollectKitTest, RequestSecurityEventInfoAsync008, TestSize.Level1)
{
    DeviceIdentify deviceIdentify = {};
    int ret = RequestSecurityEventInfoAsync(&deviceIdentify, nullptr, RequestSecurityEventInfoCallBackFunc);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);
}

/**
 * @tc.name: QuerySecurityEvent001
 * @tc.desc: DataCollectManager QuerySecurityEvent
 * @tc.type: FUNC
 * @tc.require: AR000IENKB
 */
HWTEST_F(DataCollectKitTest, QuerySecurityEvent001, TestSize.Level1)
{
    std::vector<SecurityCollector::SecurityEventRuler> rulers {};
    int ret = SecurityGuard::DataCollectManager::GetInstance().QuerySecurityEvent(rulers, nullptr);
    EXPECT_EQ(ret, SecurityGuard::NULL_OBJECT);
}

class MockNapiSecurityEventQuerier : public SecurityGuard::SecurityEventQueryCallback {
public:
    MockNapiSecurityEventQuerier() = default;
    ~MockNapiSecurityEventQuerier() override = default;
    void OnQuery(const std::vector<SecurityCollector::SecurityEvent> &events) override {};
    void OnComplete() override {};
    void OnError(const std::string &message) override {};
};

HWTEST_F(DataCollectKitTest, QuerySecurityEvent002, TestSize.Level1)
{
    std::vector<SecurityCollector::SecurityEventRuler> rulers {};
    auto callback = std::make_shared<MockNapiSecurityEventQuerier>();
    int ret = SecurityGuard::DataCollectManager::GetInstance().QuerySecurityEvent(rulers, callback);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

HWTEST_F(DataCollectKitTest, Mute001, TestSize.Level1)
{
    auto muteinfo = std::make_shared<SecurityGuard::EventMuteFilter> ();
    SecurityGuard::EventSubscribeClient client {};
    int ret = client.AddFilter(muteinfo);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);
    ret = client.AddFilter(nullptr);
    EXPECT_EQ(ret, SecurityGuard::NULL_OBJECT);
}

HWTEST_F(DataCollectKitTest, UnMute001, TestSize.Level1)
{
    auto muteinfo = std::make_shared<SecurityGuard::EventMuteFilter> ();
    SecurityGuard::EventSubscribeClient client {};
    int ret = client.RemoveFilter(muteinfo);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);
    ret = client.RemoveFilter(nullptr);
    EXPECT_EQ(ret, SecurityGuard::NULL_OBJECT);
}

HWTEST_F(DataCollectKitTest, StartCollector001, TestSize.Level1)
{
    SecurityCollector::Event event {};
    int64_t duration = 0;
    int ret = SecurityGuard::DataCollectManager::GetInstance().StartCollector(event, duration);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

HWTEST_F(DataCollectKitTest, StopCollector001, TestSize.Level1)
{
    SecurityCollector::Event event {};
    int ret = SecurityGuard::DataCollectManager::GetInstance().StopCollector(event);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

HWTEST_F(DataCollectKitTest, Mute002, testing::ext::TestSize.Level1)
{
    SecurityGuard::EventMuteFilter info {};
    SecurityGuard::SecurityEventFilter filter(info);
    Parcel parcel;
    bool ret = filter.Marshalling(parcel);
    EXPECT_TRUE(ret);
    SecurityGuard::SecurityEventFilter *retInfo = filter.Unmarshalling(parcel);
    EXPECT_FALSE(retInfo == nullptr);
}

HWTEST_F(DataCollectKitTest, Mute003, testing::ext::TestSize.Level1)
{
    SecurityGuard::EventMuteFilter info {};
    SecurityGuard::SecurityEventFilter filter(info);
    Parcel parcel {};
    int64_t int64 = 0;
    std::string string = "111";

    bool ret = filter.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);

    parcel.WriteInt64(int64);
    ret = filter.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);

    parcel.WriteInt64(int64);
    parcel.WriteInt64(int64);
    ret = filter.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);

    parcel.WriteInt64(int64);
    parcel.WriteInt64(int64);
    parcel.WriteBool(true);
    ret = filter.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);

    parcel.WriteInt64(int64);
    parcel.WriteInt64(int64);
    parcel.WriteBool(true);
    parcel.WriteString(string);
    parcel.WriteString(string);
    ret = filter.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);
    SecurityGuard::SecurityEventFilter *retInfo = filter.Unmarshalling(parcel);
    EXPECT_TRUE(retInfo == nullptr);
}

HWTEST_F(DataCollectKitTest, Mute005, testing::ext::TestSize.Level1)
{
    SecurityGuard::EventMuteFilter info {};
    SecurityGuard::SecurityEventFilter filter(info);
    Parcel parcel {};
    int64_t int64 = 0;
    uint32_t uint32 = 0;
    std::string string = "111";
    parcel.WriteInt64(int64);
    parcel.WriteInt64(int64);
    parcel.WriteBool(true);
    parcel.WriteUint32(uint32);
    bool ret = filter.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);

    parcel.WriteInt64(int64);
    parcel.WriteInt64(int64);
    parcel.WriteBool(true);
    parcel.WriteUint32(1);
    ret = filter.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);

    parcel.WriteInt64(int64);
    parcel.WriteInt64(int64);
    parcel.WriteBool(true);
    parcel.WriteUint32(1);
    parcel.WriteString(string);
    ret = filter.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
    SecurityGuard::SecurityEventFilter *retInfo = filter.Unmarshalling(parcel);
    EXPECT_TRUE(retInfo == nullptr);
}

HWTEST_F(DataCollectKitTest, Mute004, testing::ext::TestSize.Level1)
{
    SecurityGuard::EventMuteFilter info {};
    SecurityGuard::SecurityEventFilter filter(info);
    Parcel parcel {};
    int64_t int64 = 0;
    uint32_t uint32 = 10;
    std::string string = "111";
    parcel.WriteInt64(int64);
    parcel.WriteInt64(int64);
    parcel.WriteString(string);
    parcel.WriteUint32(uint32);
    parcel.WriteString(string);
    bool ret = filter.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);
    EXPECT_EQ(filter.GetMuteFilter().eventId, 0);
}

HWTEST_F(DataCollectKitTest, ReportSecurityEvent01, TestSize.Level1)
{
    int ret = SecurityGuard::DataCollectManager::GetInstance().ReportSecurityEvent(nullptr, true);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);
}

HWTEST_F(DataCollectKitTest, QuerySecurityEventConfig01, TestSize.Level1)
{
    std::string result;
    int ret = SecurityGuard::DataCollectManager::GetInstance().QuerySecurityEventConfig(result);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
}

HWTEST_F(DataCollectKitTest, ClientCreatClient01, TestSize.Level1)
{
    auto func = [](const OHOS::Security::SecurityCollector::Event &event) {};
    std::shared_ptr<SecurityGuard::EventSubscribeClient> client {};
    int32_t ret = OHOS::Security::SecurityGuard::EventSubscribeClient::CreatClient("securityGroup", func, client);
    EXPECT_EQ(ret, SecurityGuard::NO_PERMISSION);
    ret = OHOS::Security::SecurityGuard::EventSubscribeClient::CreatClient("securityGroup", nullptr, client);
    EXPECT_EQ(ret, SecurityGuard::NULL_OBJECT);
    ret = OHOS::Security::SecurityGuard::EventSubscribeClient::CreatClient("", func, client);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);
}

HWTEST_F(DataCollectKitTest, ClientSubscribe01, TestSize.Level1)
{
    auto client = std::make_shared<SecurityGuard::EventSubscribeClient>();
    int32_t ret = client->Subscribe(11);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);
}

HWTEST_F(DataCollectKitTest, ClientUnSubscribe01, TestSize.Level1)
{
    auto client = std::make_shared<SecurityGuard::EventSubscribeClient>();
    int32_t ret = client->Unsubscribe(11);
    EXPECT_EQ(ret, SecurityGuard::BAD_PARAM);
}

HWTEST_F(DataCollectKitTest, ClientSetDeathRecipient01, TestSize.Level1)
{
    auto client = std::make_shared<SecurityGuard::EventSubscribeClient>();
    OHOS::sptr<OHOS::IRemoteObject> serviceCallback =
        new (std::nothrow) SecurityGuard::AcquireDataManagerCallbackService();
    int32_t ret = SecurityGuard::EventSubscribeClient::SetDeathRecipient(client, serviceCallback);
    EXPECT_EQ(ret, SecurityGuard::SUCCESS);
}

HWTEST_F(DataCollectKitTest, ClientDeleter001, TestSize.Level1)
{
    // null client: return directly
    SecurityGuard::EventSubscribeClient::Deleter(nullptr);

    // client with callback: ClearCallBack then release, no crash on registry path
    auto *client = new SecurityGuard::EventSubscribeClient();
    client->callback_ = new (std::nothrow) SecurityGuard::AcquireDataManagerCallbackService();
    client->deathRecipient_ = new (std::nothrow) SecurityGuard::EventSubscribeClient::DeathRecipient(
        std::weak_ptr<SecurityGuard::EventSubscribeClient>());
    SecurityGuard::EventSubscribeClient::Deleter(client);
}

HWTEST_F(DataCollectKitTest, ClientConstructClientId001, TestSize.Level1)
{
    auto *serviceCallback = new (std::nothrow) SecurityGuard::AcquireDataManagerCallbackService();
    auto *otherCallback = new (std::nothrow) SecurityGuard::AcquireDataManagerCallbackService();
    std::string id1 = SecurityGuard::EventSubscribeClient::ConstructClientId(serviceCallback);
    std::string id2 = SecurityGuard::EventSubscribeClient::ConstructClientId(otherCallback);
    EXPECT_FALSE(id1.empty());
    EXPECT_FALSE(id2.empty());
    EXPECT_STRNE(id1.c_str(), id2.c_str());
    delete serviceCallback;
    delete otherCallback;
}

HWTEST_F(DataCollectKitTest, ClientSetDeathRecipient002, TestSize.Level1)
{
    // death recipient already exists: reuse it and return success
    auto client = std::make_shared<SecurityGuard::EventSubscribeClient>();
    OHOS::sptr<OHOS::IRemoteObject> serviceCallback =
        new (std::nothrow) SecurityGuard::AcquireDataManagerCallbackService();
    int32_t ret = SecurityGuard::EventSubscribeClient::SetDeathRecipient(client, serviceCallback);
    EXPECT_EQ(ret, SecurityGuard::SUCCESS);
    EXPECT_TRUE(client->deathRecipient_ != nullptr);
    auto firstRecipient = client->deathRecipient_;
    ret = SecurityGuard::EventSubscribeClient::SetDeathRecipient(client, serviceCallback);
    EXPECT_EQ(ret, SecurityGuard::SUCCESS);
    EXPECT_EQ(client->deathRecipient_, firstRecipient);
}

HWTEST_F(DataCollectKitTest, ClientClearCallBack001, TestSize.Level1)
{
    // callback is null: no-op
    auto client = std::make_shared<SecurityGuard::EventSubscribeClient>();
    client->ClearCallBack();

    // callback is set: forwarded to service, user callback no longer triggered after clear
    bool callbackInvoked = false;
    OHOS::sptr<SecurityGuard::AcquireDataManagerCallbackService> serviceCallback =
        new (std::nothrow) SecurityGuard::AcquireDataManagerCallbackService();
    serviceCallback->RegistCallBack([&callbackInvoked](const SecurityCollector::Event &event) {
        callbackInvoked = true;
    });
    client->callback_ = serviceCallback;
    client->ClearCallBack();
    std::vector<SecurityCollector::Event> events {};
    EXPECT_EQ(serviceCallback->OnNotify(events), SecurityGuard::FAILED);
    EXPECT_FALSE(callbackInvoked);
}

HWTEST_F(DataCollectKitTest, ClientOnRemoteDied001, TestSize.Level1)
{
    // weak client expired: return directly without recovery task
    auto client = std::make_shared<SecurityGuard::EventSubscribeClient>();
    SecurityGuard::EventSubscribeClient::DeathRecipient recipient(client);
    client.reset();
    const wptr<OHOS::IRemoteObject> remote {};
    recipient.OnRemoteDied(remote);
}

// Covers the "proxy is null" branches in DataCollectManager and EventSubscribeClient:
// mock samgr returns null object, iface_cast yields null proxy.
HWTEST_F(DataCollectKitTest, ManagerProxyNull001, TestSize.Level1)
{
    OHOS::sptr<OHOS::ISystemAbilityManager> mock(new (std::nothrow) NullSystemAbilityManager());
    SamgrMockGuard guard(mock);
    auto &manager = SecurityGuard::DataCollectManager::GetInstance();

    auto info = std::make_shared<SecurityGuard::EventInfo>(1, "1.0", "content");
    EXPECT_EQ(manager.ReportSecurityEvent(info, true), SecurityGuard::NULL_OBJECT);
    EXPECT_EQ(manager.SecurityGuardConfigUpdate(1, "test"), SecurityGuard::NULL_OBJECT);

    SecurityCollector::Event event {};
    EXPECT_EQ(manager.StartCollector(event, 0), SecurityGuard::NULL_OBJECT);
    EXPECT_EQ(manager.StopCollector(event), SecurityGuard::NULL_OBJECT);

    auto subscriber = std::make_shared<MockSubscriberPtr>(event);
    EXPECT_EQ(manager.Subscribe(subscriber), SecurityGuard::NULL_OBJECT);
    manager.subscribers_.insert(subscriber);
    EXPECT_EQ(manager.Unsubscribe(subscriber), SecurityGuard::NULL_OBJECT);
    manager.subscribers_.erase(subscriber);

    std::vector<SecurityCollector::SecurityEventRuler> rulers;
    auto callback = std::make_shared<MockNapiSecurityEventQuerier>();
    EXPECT_EQ(manager.QuerySecurityEvent(rulers, callback), SecurityGuard::NULL_OBJECT);
    EXPECT_EQ(manager.QuerySecurityEvent(rulers, callback, "auditGroup"), SecurityGuard::NULL_OBJECT);
    EXPECT_EQ(manager.QuerySecurityEventById(rulers, callback, "auditGroup"), SecurityGuard::NULL_OBJECT);

    std::string result;
    // QuerySecurityEventConfig returns FAILED on null object before the proxy check
    EXPECT_EQ(manager.QuerySecurityEventConfig(result), SecurityGuard::FAILED);
    EXPECT_EQ(manager.QueryAllClientsInfo(result), SecurityGuard::FAILED);

    std::string devId;
    std::string eventList;
    EXPECT_EQ(manager.RequestSecurityEventInfo(devId, eventList, nullptr), SecurityGuard::NULL_OBJECT);

    // EventSubscribeClient with the same null-object samgr
    SecurityGuard::EventSubscribeClient subscribeClient {};
    EXPECT_EQ(subscribeClient.Subscribe(11), SecurityGuard::NULL_OBJECT);
    EXPECT_EQ(subscribeClient.Unsubscribe(11), SecurityGuard::NULL_OBJECT);
    auto filter = std::make_shared<SecurityGuard::EventMuteFilter>();
    EXPECT_EQ(subscribeClient.AddFilter(filter), SecurityGuard::NULL_OBJECT);
    EXPECT_EQ(subscribeClient.RemoveFilter(filter), SecurityGuard::NULL_OBJECT);
    auto func = [](const SecurityCollector::Event &event) {};
    std::shared_ptr<SecurityGuard::EventSubscribeClient> subscribeSharedClient {};
    EXPECT_EQ(SecurityGuard::EventSubscribeClient::CreatClient("auditGroup", func, subscribeSharedClient),
        SecurityGuard::NULL_OBJECT);
}

HWTEST_F(DataCollectKitTest, TestQueryProcInfo, TestSize.Level1)
{
    SecurityCollector::SecurityEventRuler rule(11111);
    EXPECT_EQ(SecurityGuard::DataCollectManager::GetInstance().QuerySecurityEventById({rule}, nullptr, "auditGroup"),
        SecurityGuard::NULL_OBJECT);
}

HWTEST_F(DataCollectKitTest, TestQueryCodeSignInfoByPath01, TestSize.Level1)
{
    std::string result {};
    EXPECT_EQ(SecurityGuard::DataCollectManager::GetInstance().QueryCodeSignInfoByPath("test", result),
        SecurityGuard::FILE_NOT_FOUND);
}

HWTEST_F(DataCollectKitTest, TestQueryCodeSignInfoByPath02, TestSize.Level1)
{
    std::string result {};
    std::string path = "/data/test/unittest/resource/security_guard/security_guard/security_guard_cache_event.cfg";
    EXPECT_EQ(SecurityGuard::DataCollectManager::GetInstance().QueryCodeSignInfoByPath(path, result),
        SecurityGuard::NO_PERMISSION);
}

HWTEST_F(DataCollectKitTest, TestQueryAllClientsInfo, TestSize.Level1)
{
    std::string result {};
    EXPECT_EQ(SecurityGuard::DataCollectManager::GetInstance().QueryAllClientsInfo(result),
        SecurityGuard::NO_PERMISSION);
}
}