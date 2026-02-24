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

#include "inner_sdk_fuzzer.h"

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
#ifndef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
#include "risk_analysis_manager_callback_service.h"
#include "risk_analysis_manager_callback_stub.h"
#include "risk_analysis_manager_callback.h"
#include "risk_analysis_manager_proxy.h"
#endif
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

#ifndef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
class MockRiskAnalysisManagerCallbackStub : public RiskAnalysisManagerCallbackStub {
public:
    MockRiskAnalysisManagerCallbackStub() = default;
    ~MockRiskAnalysisManagerCallbackStub() override = default;
    int32_t ResponseSecurityModelResult(const std::string &devId, uint32_t modelId, std::string &result) override
    {
        return 0;
    };
};
#endif
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


void AcquireDataManagerFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int fd = fdp.ConsumeIntegral<int32_t>();
    int64_t eventId = fdp.ConsumeIntegral<int64_t>();
    std::string string = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    Security::SecurityCollector::Event event{eventId, string, string, string};
    auto subscriber = std::make_shared<MockCollectorSubscriber>(event);
    auto callback = std::make_shared<MockSecurityEventQueryCallback>();
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    DataCollectManager::GetInstance().Subscribe(subscriber);
    DataCollectManager::GetInstance().Unsubscribe(subscriber);
    DataCollectManager::GetInstance().StartCollector(event, eventId);
    DataCollectManager::GetInstance().StopCollector(event);
    DataCollectManager::GetInstance().QuerySecurityEventConfig(string);
    std::vector<SecurityEventRuler> rulers{};
    DataCollectManager::GetInstance().QuerySecurityEvent(rulers, callback);
    DataCollectManager::GetInstance().SecurityGuardConfigUpdate(fd, string);
    DataCollectManager::GetInstance().QuerySecurityEventById(rulers, callback, "auditGroup");
    std::string result {};
    DataCollectManager::GetInstance().QueryCodeSignInfoByPath(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE), result);
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
void AcquireDataManagerCallbackServiceFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    size_t offset = 0;
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data + offset));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    Security::SecurityCollector::Event event{eventId, string, string, string};
    AcquireDataManagerCallbackService service;
    service.OnNotify({event});
}

void AcquireDataManagerCallbackStubFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    size_t offset = 0;
    MockAcquireDataManagerCallbackStub stub;
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    int64_t int64 = *(reinterpret_cast<const int64_t *>(data + offset));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    datas.WriteInterfaceToken(AcquireDataManagerCallbackStub::GetDescriptor());
    datas.WriteInt64(int64);
    datas.WriteString(string);
    datas.WriteString(string);
    datas.WriteString(string);
    stub.OnRemoteRequest(AcquireDataManagerCallbackStub::CMD_DATA_SUBSCRIBE_CALLBACK, datas, reply, option);
}
#ifndef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
void RiskAnalysisManagerCallbackStubFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }
    size_t offset = 0;
    MockRiskAnalysisManagerCallbackStub stub;
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = *(reinterpret_cast<const uint32_t *>(data + offset));
    offset += sizeof(uint32_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    datas.WriteInterfaceToken(IRiskAnalysisManagerCallback::GetDescriptor());
    datas.WriteUint32(*(reinterpret_cast<const uint32_t *>(data)));
    datas.WriteString(string);
    datas.WriteString(string);
    stub.OnRemoteRequest(code, datas, reply, option);

    ResultCallback callback;
    RiskAnalysisManagerCallbackService service(callback);
    service.ResponseSecurityModelResult(string, code, string);
    service.callback_ = TestResultCallback;
    service.ResponseSecurityModelResult(string, code, string);
}

void RiskAnalysisManagerProxyFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }
    size_t offset = 0;
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    ResultCallback func = [] (const std::string &devId, uint32_t modelId, const std::string &result) -> int32_t {
        return 0;
    };
    sptr<RiskAnalysisManagerCallbackService> callback = new (std::nothrow) RiskAnalysisManagerCallbackService(func);
    uint32_t uint32 = *(reinterpret_cast<const uint32_t *>(data));
    offset += sizeof(uint32_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    RiskAnalysisManagerProxy proxy{obj};
    proxy.RequestSecurityModelResult(string, uint32, string, callback);
    proxy.SetModelState(uint32, true);
}
#endif
void CollectorManagerFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    Security::SecurityCollector::Event event{fdp.ConsumeIntegral<int64_t>(),
        fdp.ConsumeRandomLengthString(MAX_STRING_SIZE), fdp.ConsumeRandomLengthString(MAX_STRING_SIZE),
        fdp.ConsumeRandomLengthString(MAX_STRING_SIZE)};
    auto subscriber = std::make_shared<MockCollectorSubscriber>(event);
    std::vector<SecurityEventRuler> rulers{};
    std::vector<SecurityEvent> events{};
    SecurityCollectorSubscribeInfo subscribeInfo{};
    CollectorManager::GetInstance().Subscribe(subscriber);
    CollectorManager::GetInstance().Unsubscribe(subscriber);
    CollectorManager::GetInstance().QuerySecurityEvent(rulers, events);
    CollectorManager::GetInstance().CollectorStart(subscribeInfo);
    CollectorManager::GetInstance().CollectorStop(subscribeInfo);

    CollectorManager manager;
    sptr<Security::SecurityCollector::SecurityCollectorManagerCallbackService> callback =
        new (std::nothrow) Security::SecurityCollector::SecurityCollectorManagerCallbackService(nullptr);
    manager.eventListeners_[subscriber] = callback;
    manager.Subscribe(nullptr);
    manager.Subscribe(subscriber);
    manager.Unsubscribe(nullptr);
    manager.Unsubscribe(subscriber);
    SecurityCollectorEventMuteFilter filter {};
    filter.eventId = fdp.ConsumeIntegral<int64_t>();
    filter.type = fdp.ConsumeIntegral<int64_t>();
    filter.isSetMute = static_cast<bool>(fdp.ConsumeBool());
    filter.mutes.insert(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    SecurityCollectorEventFilter subscribeMute(filter);
    CollectorManager::GetInstance().AddFilter(subscribeMute);
    CollectorManager::GetInstance().RemoveFilter(subscribeMute);
    Parcel parcel;
    subscribeMute.ReadFromParcel(parcel);
    subscribeMute.Marshalling(parcel);
    subscribeMute.Unmarshalling(parcel);
}

void DataCollectManagerCallbackStubFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }
    size_t offset = 0;
    MockDataCollectManagerCallbackStub stub;
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    uint32_t uint32 = *(reinterpret_cast<const uint32_t *>(data + offset));
    offset += sizeof(uint32_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
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

void SecurityCollectorManagerCallbackStubFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t) + sizeof(uint32_t)) {
        return;
    }
    size_t offset = 0;
    MockSecurityCollectorManagerCallbackStub stub;
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = *(reinterpret_cast<const uint32_t *>(data + offset));
    offset += sizeof(uint32_t);
    uint32_t uint32 = *(reinterpret_cast<const uint32_t *>(data + offset));
    offset += sizeof(uint32_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    datas.WriteInterfaceToken(ISecurityCollectorManagerCallback::GetDescriptor());
    datas.WriteUint32(uint32);
    datas.WriteString(string);
    datas.WriteString(string);
    datas.WriteString(string);
    stub.OnRemoteRequest(code, datas, reply, option);
}

void SecurityCollectorManagerProxyFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    sptr<Security::SecurityCollector::SecurityCollectorManagerCallbackService> callback =
        new (std::nothrow) Security::SecurityCollector::SecurityCollectorManagerCallbackService(nullptr);
    std::string string(reinterpret_cast<const char *>(data), size);
    int64_t int64 = *(reinterpret_cast<const int64_t *>(data));
    SecurityCollectorSubscribeInfo subscribeInfo({int64, string, string, string});
    SecurityCollectorManagerProxy proxy{obj};
    std::vector<SecurityEventRuler> rulers{};
    std::vector<SecurityEvent> events{};
    proxy.Subscribe(subscribeInfo, callback);
    proxy.Unsubscribe(callback);
    proxy.CollectorStart(subscribeInfo, callback);
    proxy.CollectorStop(subscribeInfo, callback);
    proxy.QuerySecurityEvent(rulers, events);
}

void SecurityCollectorSubscribeInfoFuzzTest(const uint8_t* data, size_t size)
{
    std::string string(reinterpret_cast<const char*>(data), size);
    int64_t int64 = static_cast<int64_t>(size);
    SecurityCollectorSubscribeInfo info;
    Parcel parcel;
    info.Marshalling(parcel);
    info.Unmarshalling(parcel);
    info.ReadFromParcel(parcel);

    parcel.WriteInt64(int64);
    info.ReadFromParcel(parcel);

    parcel.WriteInt64(int64);
    parcel.WriteBool(true);
    info.ReadFromParcel(parcel);

    parcel.WriteInt64(int64);
    parcel.WriteBool(true);
    parcel.WriteInt64(int64);
    info.ReadFromParcel(parcel);

    parcel.WriteInt64(int64);
    parcel.WriteBool(true);
    parcel.WriteInt64(int64);
    parcel.WriteString(string);
    info.ReadFromParcel(parcel);

    parcel.WriteInt64(int64);
    parcel.WriteBool(true);
    parcel.WriteInt64(int64);
    parcel.WriteString(string);
    parcel.WriteString(string);
    info.ReadFromParcel(parcel);

    parcel.WriteInt64(int64);
    parcel.WriteBool(true);
    parcel.WriteInt64(int64);
    parcel.WriteString(string);
    parcel.WriteString(string);
    parcel.WriteString(string);
    info.ReadFromParcel(parcel);

    info.Unmarshalling(parcel);
}

void SecurityEventFuzzTest(const uint8_t* data, size_t size)
{
    std::string string(reinterpret_cast<const char*>(data), size);
    int64_t int64 = static_cast<int64_t>(size);
    SecurityEvent event;
    Parcel parcel;
    event.Marshalling(parcel);
    event.Unmarshalling(parcel);
    event.ReadFromParcel(parcel);

    parcel.WriteInt64(int64);
    event.ReadFromParcel(parcel);

    parcel.WriteInt64(int64);
    parcel.WriteString(string);
    event.ReadFromParcel(parcel);

    parcel.WriteInt64(int64);
    parcel.WriteString(string);
    parcel.WriteString(string);
    event.ReadFromParcel(parcel);

    event.Unmarshalling(parcel);
}

void SecurityEventRulerFuzzTest(const uint8_t* data, size_t size)
{
    std::string string(reinterpret_cast<const char*>(data), size);
    int64_t int64 = static_cast<int64_t>(size);
    SecurityEventRuler ruler;
    Parcel parcel;
    ruler.Marshalling(parcel);
    ruler.Unmarshalling(parcel);
    ruler.ReadFromParcel(parcel);

    parcel.WriteInt64(int64);
    ruler.ReadFromParcel(parcel);

    parcel.WriteInt64(int64);
    parcel.WriteString(string);
    ruler.ReadFromParcel(parcel);

    parcel.WriteInt64(int64);
    parcel.WriteString(string);
    parcel.WriteString(string);
    ruler.ReadFromParcel(parcel);

    parcel.WriteInt64(int64);
    parcel.WriteString(string);
    parcel.WriteString(string);
    parcel.WriteString(string);
    ruler.ReadFromParcel(parcel);

    ruler.Unmarshalling(parcel);
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
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    OHOS::AcquireDataManagerFuzzTest(data, size);
    OHOS::AcquireDataManagerCallbackServiceFuzzTest(data, size);
    OHOS::AcquireDataManagerCallbackStubFuzzTest(data, size);
#ifndef SECURITY_GUARD_TRIM_MODEL_ANALYSIS
    OHOS::RiskAnalysisManagerCallbackStubFuzzTest(data, size);
    OHOS::RiskAnalysisManagerProxyFuzzTest(data, size);
#endif
    OHOS::CollectorManagerFuzzTest(data, size);
    OHOS::DataCollectManagerCallbackStubFuzzTest(data, size);
    OHOS::SecurityCollectorManagerCallbackStubFuzzTest(data, size);
    OHOS::SecurityCollectorManagerProxyFuzzTest(data, size);
    OHOS::SecurityCollectorSubscribeInfoFuzzTest(data, size);
    OHOS::SecurityEventFuzzTest(data, size);
    OHOS::SecurityEventRulerFuzzTest(data, size);
    OHOS::DataCollectManagerFuzzTest(data, size);
    OHOS::EventSubscribeClientFuzzTest(data, size);
    return 0;
}