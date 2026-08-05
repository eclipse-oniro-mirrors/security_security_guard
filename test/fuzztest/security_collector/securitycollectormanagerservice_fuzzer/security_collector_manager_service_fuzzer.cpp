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

#include "security_collector_manager_service_fuzzer.h"

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

void SecurityCollectorManagerServiceFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int fd = fdp.ConsumeIntegral<int32_t>();
    int32_t systemAbilityId = fdp.ConsumeIntegral<int32_t>();
    int64_t eventId = fdp.ConsumeIntegral<int64_t>();
    std::string string = fdp.ConsumeRandomLengthString(MAX_STRING_SIZE);
    SecurityCollectorEventMuteFilter fil{};
    std::vector<std::u16string> args;
    SecurityCollectorManagerService service(SECURITY_COLLECTOR_MANAGER_SA_ID, false);
    Security::SecurityCollector::Event event{};
    event.eventId = eventId;
    event.version = string;
    event.content = string;
    event.extra = string;
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    SecurityEventRuler ruler(eventId);
    std::vector<SecurityEventRuler> rulers;
    rulers.emplace_back(ruler);
    SecurityCollectorSubscribeInfo subscribeInfo{event};
    ScSubscribeEvent scEvent{};
    ScUnsubscribeEvent scuEvent{};
    scEvent.eventId = eventId;
    std::vector<SecurityEvent> events{};
    service.Dump(fd, args);
    service.OnAddSystemAbility(systemAbilityId, string);
    service.OnRemoveSystemAbility(systemAbilityId, string);
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
    service.ExecuteOnNotifyByTask(nullptr, event);
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
    Security::SecurityCollector::Event event{};
    event.eventId = eventId;
    event.version = string;
    event.content = string;
    event.extra = string;
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
    Security::SecurityCollector::Event event{};
    event.eventId = eventId;
    event.version = string;
    event.content = string;
    event.extra = string;
    auto subscriber = std::make_shared<SecurityCollectorSubscriber>(string, subscriberInfo, nullptr,
        [] (const std::string &appName, const sptr<IRemoteObject> &remote, const Event &event) {});
    sptr<IRemoteObject> obj(new (std::nothrow) MockRemoteObject());
    SecurityCollectorSubscriberManager::GetInstance().SubscribeCollector(subscriber);
    SecurityCollectorSubscriberManager::GetInstance().UnsubscribeCollector(obj);
    SecurityCollectorSubscriberManager::GetInstance().FindEventIds(obj);
    SecurityCollectorSubscriberManager::CollectorListenner listener{subscriber};
    listener.GetExtraInfo();
    SecurityCollectorSubscriberManager::GetInstance().GetAppSubscribeCount(string);
    SecurityCollectorSubscriberManager::GetInstance().GetAppSubscribeCount(string, eventId);
    SecurityCollectorSubscriberManager::GetInstance().NotifySubscriber(event);
}

}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    OHOS::SecurityCollectorManagerServiceFuzzTest(data, size);
    OHOS::SecurityCollectorRunManagerFuzzTest(data, size);
    OHOS::SecurityCollectorSubscriberManagerFuzzTest(data, size);
    return 0;
}
