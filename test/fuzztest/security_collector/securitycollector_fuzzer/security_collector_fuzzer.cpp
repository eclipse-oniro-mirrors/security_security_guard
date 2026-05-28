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

#include "security_collector_fuzzer.h"

#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "securec.h"

#define private public
#define protected public
#include "collector_cfg_marshalling.h"
#include "data_collection.h"
#include "lib_loader.h"
#include "security_collector_manager_callback_proxy.h"
#include "security_collector_manager_service.h"
#include "security_collector_manager_stub.h"
#include "security_collector_run_manager.h"
#include "security_collector_subscriber_manager.h"
#include "security_collector_subscriber.h"
#include "event_define.h"
#undef private
#undef protected

using namespace OHOS::Security::SecurityCollector;
namespace {
    constexpr int MAX_STRING_SIZE = 1024;
}
namespace OHOS {
class MockRemoteObject final : public IRemoteObject {
public:
    MockRemoteObject() : IRemoteObject(u"")
    {
    }
    int32_t GetObjectRefCount() { return 0; };
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) { return 0; };
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; };
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; };
    int Dump(int fd, const std::vector<std::u16string> &args) { return 0; };
};

void DataCollectionFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t) + sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    SecurityCollectorEventMuteFilter fil{};
    int32_t collectorType = fdp.ConsumeIntegral<int32_t>();
    int64_t eventId = fdp.ConsumeIntegral<int64_t>();
    std::string string = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    SecurityCollectorSubscribeInfo subseciberInfo{};
    auto subscriber = std::make_shared<SecurityCollectorSubscriber>(string, subseciberInfo, nullptr,
        [] (const std::string &appName, const sptr<IRemoteObject> &remote, const Event &event) {});
    auto collectorListenner = std::make_shared<SecurityCollectorRunManager::CollectorListenner>(subscriber);
    std::vector<int64_t> eventIds{eventId};
    SecurityEventRuler ruler{eventId};
    std::vector<SecurityEventRuler> rulers;
    rulers.emplace_back(ruler);
    std::vector<SecurityEvent> events{};
    std::ifstream stream{string};
    DataCollection::GetInstance().StopCollectors(eventIds);
    DataCollection::GetInstance().GetCollectorType(eventId, collectorType);
    DataCollection::GetInstance().QuerySecurityEvent(rulers, events);
    DataCollection::GetInstance().LoadCollector(eventId, string, collectorListenner);
    DataCollection::GetInstance().LoadCollector(string, ruler, events);
    DataCollection::GetInstance().GetCollectorPath(eventId, string);
    DataCollection::GetInstance().CheckFileStream(stream);
    DataCollection::GetInstance().IsCollectorStarted(eventId);
    DataCollection::GetInstance().SecurityGuardSubscribeCollector(eventIds);
}

void LibLoaderFuzzTest(const uint8_t* data, size_t size)
{
    std::string string(reinterpret_cast<const char*>(data), size);
    LibLoader loader{string};
    loader.LoadLib();
    loader.CallGetCollector();
    loader.UnLoadLib();
}

void SecurityCollectorManagerCallbackProxyFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    Security::SecurityCollector::Event event{};
    event.eventId = fdp.ConsumeIntegral<int64_t>();
    event.version = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    event.content = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    event.extra = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    SecurityCollectorManagerCallbackProxy proxy{obj};
    proxy.OnNotify(event);
}

class TestCollector : public ICollector {
public:
    int Start(std::shared_ptr<ICollectorFwk> api) override {return 0;};
    int Stop()  override {return 0;};
};


void SecurityCollectorICollectorFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    TestCollector collector;
    SecurityCollectorEventMuteFilter collectorFilter {};
    collectorFilter.eventId = fdp.ConsumeIntegral<int64_t>();
    collectorFilter.mutes.insert(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    SecurityEvent event {};
    event.eventId_ = fdp.ConsumeIntegral<int64_t>();
    event.content_ = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    event.version_ = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    event.timestamp_ = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);

    std::vector<SecurityEvent> eventIds {};
    eventIds.emplace_back(event);
    SecurityEventRuler ruler;
    ruler.eventId_ = fdp.ConsumeIntegral<int64_t>();
    ruler.beginTime_ = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    ruler.endTime_ = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    ruler.param_ = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    collector.IsStartWithSub();
    collector.Query(ruler, eventIds);
    collector.Unsubscribe(fdp.ConsumeIntegral<int64_t>());
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    OHOS::DataCollectionFuzzTest(data, size);
    OHOS::LibLoaderFuzzTest(data, size);
    OHOS::SecurityCollectorManagerCallbackProxyFuzzTest(data, size);
    return 0;
}
