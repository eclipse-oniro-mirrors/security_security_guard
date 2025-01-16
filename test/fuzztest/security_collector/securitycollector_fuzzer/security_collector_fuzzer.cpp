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
    size_t offset = 0;
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data));
    offset += sizeof(int64_t);
    int32_t collectorType = *(reinterpret_cast<const int32_t *>(data + offset));
    offset += sizeof(int32_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
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
    DataCollection::GetInstance().StartCollectors(eventIds, collectorListenner);
    DataCollection::GetInstance().StopCollectors(eventIds);
    DataCollection::GetInstance().GetCollectorType(eventId, collectorType);
    DataCollection::GetInstance().QuerySecurityEvent(rulers, events);
    DataCollection::GetInstance().LoadCollector(eventId, string, collectorListenner);
    DataCollection::GetInstance().LoadCollector(string, ruler, events);
    DataCollection::GetInstance().GetCollectorPath(eventId, string);
    DataCollection::GetInstance().CheckFileStream(stream);
    DataCollection::GetInstance().IsCollectorStarted(eventId);
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
    size_t offset = 0;
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    Security::SecurityCollector::Event event{eventId, string, string, string};
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    SecurityCollectorManagerCallbackProxy proxy{obj};
    proxy.OnNotify(event);
}

void SecurityCollectorManagerServiceFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    size_t offset = 0;
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    SecurityCollectorManagerService service(SECURITY_COLLECTOR_MANAGER_SA_ID, false);
    Security::SecurityCollector::Event event{eventId, string, string, string};
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    SecurityEventRuler ruler(eventId);
    std::vector<SecurityEventRuler> rulers;
    rulers.emplace_back(ruler);
    SecurityCollectorSubscribeInfo subscribeInfo{event};
    ScSubscribeEvent scEvent{};
    ScUnsubscribeEvent scuEvent{};
    scEvent.eventId = eventId;
    std::vector<SecurityEvent> events{};
    service.Subscribe(subscribeInfo, obj);
    service.Unsubscribe(obj);
    service.CollectorStop(subscribeInfo, obj);
    service.CollectorStart(subscribeInfo, obj);
    service.QuerySecurityEvent(rulers, events);
    SecurityCollectorManagerService::ReportScSubscribeEvent(scEvent);
    SecurityCollectorManagerService::ReportScUnsubscribeEvent(scuEvent);
    SecurityCollectorManagerService::GetAppName();
    SecurityCollectorManagerService::HasPermission(string);
    service.CleanSubscriber(obj);
    service.ExecuteOnNotifyByTask(obj, event);
}

void SecurityCollectorManagerServiceNewFuzzTest(const uint8_t* data, size_t size)
{
    SecurityCollectorManagerService service(SECURITY_COLLECTOR_MANAGER_SA_ID, false);
    FuzzedDataProvider fdp(data, size);
    SecurityCollectorEventMuteFilter fil {};
    fil.eventId = fdp.ConsumeIntegral<int64_t>();
    fil.mutes.emplace_back(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    fil.isSetMute = fdp.ConsumeBool();
    fil.type = static_cast<SecurityCollectorEventMuteType>(fdp.ConsumeIntegral<int64_t>());
    SecurityCollectorEventFilter filter(fil);
    service.Mute(filter, fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    service.Unmute(filter, fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
}

void SecurityCollectorRunManagerFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    size_t offset = 0;
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    Security::SecurityCollector::Event event{eventId, string, string, string};
    SecurityCollectorSubscribeInfo subscriberInfo{};
    auto subscriber = std::make_shared<SecurityCollectorSubscriber>(string, subscriberInfo, nullptr,
        [] (const std::string &appName, const sptr<IRemoteObject> &remote, const Event &event) {});
    SecurityCollectorRunManager manager;
    manager.StartCollector(subscriber);
    manager.StopCollector(subscriber);
    SecurityCollectorRunManager::CollectorListenner listener{subscriber};
    listener.GetExtraInfo();
    listener.OnNotify(event);
}

void SecurityCollectorSubscriberManagerFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    size_t offset = 0;
    int64_t eventId = *(reinterpret_cast<const int64_t *>(data));
    offset += sizeof(int64_t);
    std::string string(reinterpret_cast<const char*>(data + offset), size - offset);
    SecurityCollectorSubscribeInfo subscriberInfo{};
    Security::SecurityCollector::Event event{eventId, string, string, string};
    auto subscriber = std::make_shared<SecurityCollectorSubscriber>(string, subscriberInfo, nullptr,
        [] (const std::string &appName, const sptr<IRemoteObject> &remote, const Event &event) {});
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    SecurityCollectorSubscriberManager::GetInstance().SubscribeCollector(subscriber);
    SecurityCollectorSubscriberManager::GetInstance().UnsubscribeCollector(obj);
    SecurityCollectorSubscriberManager::GetInstance().FindEventIds(obj);
    SecurityCollectorSubscriberManager::GetInstance().GetAppSubscribeCount(string);
    SecurityCollectorSubscriberManager::GetInstance().GetAppSubscribeCount(string, eventId);
    SecurityCollectorSubscriberManager::GetInstance().NotifySubscriber(event);
    SecurityCollectorSubscriberManager::CollectorListenner listener{subscriber};
    listener.GetExtraInfo();
    listener.OnNotify(event);
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
    collectorFilter.mutes.emplace_back(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
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
    collector.Mute(collectorFilter, fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    collector.Unmute(collectorFilter, fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
    collector.Query(ruler, eventIds);
    collector.Subscribe(fdp.ConsumeIntegral<int64_t>());
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
    OHOS::SecurityCollectorManagerServiceFuzzTest(data, size);
    OHOS::SecurityCollectorRunManagerFuzzTest(data, size);
    OHOS::SecurityCollectorSubscriberManagerFuzzTest(data, size);
    return 0;
}
