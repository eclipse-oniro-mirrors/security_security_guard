/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "datacollectmanager_sdk_fuzzer.h"

#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "securec.h"

#define private public
#define protected public
#include "data_collect_manager.h"
#include "event_subscribe_client.h"
#include "acquire_data_manager_callback_service.h"
#include "acquire_data_manager_callback_stub.h"
#include "data_collect_manager_callback_service.h"
#include "data_collect_manager_callback_stub.h"
#include "data_collect_manager_idl_proxy.h"
#include "collector_manager.h"
#include "security_collector_manager_callback_stub.h"
#include "security_collector_manager_proxy.h"
#include "security_collector_subscribe_info.h"
#include "security_event.h"
#include "security_event_ruler.h"
#include "security_event_query_callback_service.h"
#undef private
#undef protected

using namespace OHOS::Security::SecurityGuard;
using namespace OHOS::Security::SecurityCollector;
namespace {
    constexpr int MAX_STRING_SIZE = 1024;
    OHOS::sptr<OHOS::IPCObjectProxy::DeathRecipient> ret {};
}
namespace OHOS {
class MockCollectorSubscriber : public ICollectorSubscriber {
public:
    explicit MockCollectorSubscriber(const Event &event) : ICollectorSubscriber(event) {};
    int32_t OnNotify(const Event &event) override { return 0; };
};

class MockRemoteObject final : public IRemoteObject {
public:
    MockRemoteObject() : IRemoteObject(u"")
    {
    }
    int32_t GetObjectRefCount() { return 0; };
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) { return 0; };
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient)
    {
        ret = recipient;
        return true;
    };
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; };
    int Dump(int fd, const std::vector<std::u16string> &args) { return 0; };
};

class MockAcquireDataManagerCallbackStub : public AcquireDataManagerCallbackStub {
public:
    explicit MockAcquireDataManagerCallbackStub() = default;
    ~MockAcquireDataManagerCallbackStub() override = default;
    int32_t OnNotify(const std::vector<Security::SecurityCollector::Event> &events) override { return 0; };
};

class MockSecurityCollectorManagerCallbackStub : public SecurityCollectorManagerCallbackStub {
public:
    MockSecurityCollectorManagerCallbackStub() = default;
    ~MockSecurityCollectorManagerCallbackStub() override = default;

    int32_t OnNotify(const Event &event) override { return 0; };
};

class MockDataCollectManagerCallbackStub : public DataCollectManagerCallbackStub {
public:
    MockDataCollectManagerCallbackStub() = default;
    ~MockDataCollectManagerCallbackStub() override = default;

    int32_t ResponseRiskData(std::string &devId, std::string &riskData, uint32_t status,
        const std::string& errMsg = "") override { return 0; };
};

class MockSecurityEventQueryCallback : public SecurityEventQueryCallback {
public:
    MockSecurityEventQueryCallback() = default;
    ~MockSecurityEventQueryCallback() override = default;
    void OnQuery(const std::vector<SecurityEvent> &events) override {};
    void OnComplete() override {};
    void OnError(const std::string &message) override {};
};

int32_t TestRequestRiskDataCallback(std::string &, std::string &, uint32_t, const std::string &)
{
    return 0;
}

int32_t TestResultCallback(const std::string &devId, uint32_t modelId, const std::string &result)
{
    return 0;
}


void DataCollectManagerFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    EventSubscribeClient client {};
    auto mute = std::make_shared<Security::SecurityGuard::EventMuteFilter>();
    mute->eventId = fdp.ConsumeIntegral<int64_t>();
    mute->type = fdp.ConsumeIntegral<int64_t>();
    mute->isInclude = fdp.ConsumeIntegral<bool>();
    mute->mutes.insert(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    client.AddFilter(mute);
    client.RemoveFilter(mute);
    auto func = [] (std::string &devId, std::string &riskData, uint32_t status,
        const std::string &errMsg)-> int32_t {
        return 0;
    };
    std::string string = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    std::string string1 = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    DataCollectManager::GetInstance().RequestSecurityEventInfo(string, string1, func);
}

void DataCollectManagerCallbackStubFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    MockDataCollectManagerCallbackStub stub;
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    uint32_t uint32 = fdp.ConsumeIntegral<uint32_t>();
    std::string string(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    datas.WriteInterfaceToken(IDataCollectManagerCallback::GetDescriptor());
    datas.WriteString(string);
    datas.WriteUint32(uint32);
    datas.WriteString(string);
    stub.OnRemoteRequest(DataCollectManagerCallbackStub::CMD_SET_REQUEST_DATA, datas, reply, option);

    RequestRiskDataCallback callback;
    DataCollectManagerCallbackService service(callback);
    service.ResponseRiskData(string, string, uint32, string);
    service.callback_ = TestRequestRiskDataCallback;
    service.ResponseRiskData(string, string, uint32, string);
}

void EventSubscribeClientFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    EventSubscribeClient client {};
    std::shared_ptr<EventSubscribeClient> client1;
    auto func = [] (const Security::SecurityCollector::Event &event) {
    };
    EventSubscribeClient::CreatClient(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE), func, client1);
    client.Subscribe(fdp.ConsumeIntegral<int64_t>());
    client.Unsubscribe(fdp.ConsumeIntegral<int64_t>());

    // Deleter: null client and valid client with callback/recipient
    EventSubscribeClient::Deleter(nullptr);
    auto *rawClient = new EventSubscribeClient();
    rawClient->callback_ = new (std::nothrow) AcquireDataManagerCallbackService();
    rawClient->deathRecipient_ =
        new (std::nothrow) EventSubscribeClient::DeathRecipient{std::weak_ptr<EventSubscribeClient>()};
    EventSubscribeClient::Deleter(rawClient);

    // SetDeathRecipient: first call creates recipient, second reuses it
    auto validClient = std::make_shared<EventSubscribeClient>();
    sptr<IRemoteObject> remote(new (std::nothrow) MockRemoteObject());
    EventSubscribeClient::SetDeathRecipient(validClient, remote);
    EventSubscribeClient::SetDeathRecipient(validClient, remote);

    // ReconnectService: real samgr with recipient already set
    validClient->ReconnectService();

    // OnRemoteDied: expired weak client returns directly
    sptr<EventSubscribeClient::DeathRecipient> expiredRecipient =
        new EventSubscribeClient::DeathRecipient {std::weak_ptr<EventSubscribeClient>()};
    expiredRecipient->OnRemoteDied(wptr<IRemoteObject>(remote));

    // OnRemoteDied: valid client, mocked ffrt submit runs HandleDeath synchronously
    sptr<EventSubscribeClient::DeathRecipient> recipient =
        new EventSubscribeClient::DeathRecipient {validClient};
    recipient->OnRemoteDied(wptr<IRemoteObject>(remote));

    // HandleDeath directly: mocked sleep makes the retry loop finish fast
    validClient->HandleDeath();
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    OHOS::DataCollectManagerCallbackStubFuzzTest(data, size);
    OHOS::DataCollectManagerFuzzTest(data, size);
    OHOS::EventSubscribeClientFuzzTest(data, size);
    return 0;
}