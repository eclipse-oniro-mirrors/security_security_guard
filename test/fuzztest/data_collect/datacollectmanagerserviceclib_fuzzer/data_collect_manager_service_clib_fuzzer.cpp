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

#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "securec.h"
#include <string_ex.h>
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"
#define private public
#define protected public
#include "event_define.h"
#include "acquire_data_subscribe_manager.h"
#include "acquire_data_callback_proxy.h"
#include "data_collect_manager_callback_proxy.h"
#include "data_collect_manager_service.h"
#include "data_collect_manager_idl_stub.h"
#include "security_event_query_callback_proxy.h"
#include "database_helper.h"
#include "database_manager.h"
#include "database.h"
#include "risk_event_rdb_helper.h"
#include "store_define.h"
#undef private
#undef prtected
using namespace OHOS;
using namespace OHOS::Security::SecurityGuard;
namespace {
    constexpr int MAX_STRING_SIZE = 1024;
    constexpr int TEST_SA_ID = 3524;
    OHOS::sptr<OHOS::IPCObjectProxy::DeathRecipient> ret {};
}
namespace OHOS {
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
}  // namespace OHOS
DataCollectManagerService g_service(TEST_SA_ID, true);
void SetPermission()
{
    static const char *permission[] = {
        "ohos.permission.securityguard.REPORT_SECURITY_INFO",
        "ohos.permission.REPORT_SECURITY_EVENT",
        "ohos.permission.securityguard.REQUEST_SECURITY_EVENT_INFO",
        "ohos.permission.MANAGE_SECURITY_GUARD_CONFIG",
        "ohos.permission.QUERY_SECURITY_EVENT",
        "ohos.permission.QUERY_AUDIT_EVENT"
    };
    uint64_t tokenId;
    NativeTokenInfoParams infoParams = {
        .dcapsNum = 0,
        .permsNum = 6,
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
extern "C" int FuzzDataCollectManagerService(FuzzedDataProvider &fdp)
{
    static const int ipccode[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19};
    int code = fdp.PickValueInArray(ipccode);
    switch (code) {
        case 0: {
            int32_t systemAbilityId = fdp.ConsumeIntegral<int32_t>();
            const std::string deviceId = fdp.ConsumeRandomLengthString();
            g_service.OnAddSystemAbility(systemAbilityId, deviceId);
            break;
        }
        case 1: {
            int64_t evenId = fdp.ConsumeIntegral<int64_t>();
            const std::string version = fdp.ConsumeRandomLengthString();
            const std::string time = fdp.ConsumeRandomLengthString();
            const std::string content = fdp.ConsumeRandomLengthString();
            g_service.RequestDataSubmit(evenId, version, time, content);
            break;
        }
        case 2: {
            int64_t eventId = fdp.ConsumeIntegral<int64_t>();
            const std::string version = fdp.ConsumeRandomLengthString();
            const std::string time = fdp.ConsumeRandomLengthString();
            const std::string content = fdp.ConsumeRandomLengthString();
            g_service.RequestDataSubmitAsync(eventId, version, time, content);
            break;
        }
        case 3: {
            const std::string deviceId = fdp.ConsumeRandomLengthString();
            const std::string eventList = fdp.ConsumeRandomLengthString();
            sptr<OHOS::IRemoteObject> obj(new (std::nothrow) OHOS::MockRemoteObject());
            g_service.RequestRiskData(deviceId, eventList, obj);
            break;
        }
        case 4: {
            int64_t eventId = fdp.ConsumeIntegral<int64_t>();
            const std::string string = fdp.ConsumeRandomLengthString();
            const std::string clientId = fdp.ConsumeRandomLengthString();
            Security::SecurityCollector::Event event{eventId, string, string, string};
            Security::SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{event};
            sptr<OHOS::IRemoteObject> obj(new (std::nothrow) OHOS::MockRemoteObject());
            g_service.Subscribe(subscribeInfo, obj, clientId);
            break;
        }
        case 5: {
            int64_t eventId = fdp.ConsumeIntegral<int64_t>();
            const std::string string = fdp.ConsumeRandomLengthString();
            const std::string clientId = fdp.ConsumeRandomLengthString();
            Security::SecurityCollector::Event event{eventId, string, string, string};
            Security::SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{event};
            sptr<OHOS::IRemoteObject> obj(new (std::nothrow) OHOS::MockRemoteObject());
            g_service.Unsubscribe(subscribeInfo, obj, clientId);
            break;
        }
        case 6: {
            int64_t eventId = fdp.ConsumeIntegral<int64_t>();
            OHOS::Security::SecurityCollector::SecurityEventRuler ruler{eventId};
            std::vector<OHOS::Security::SecurityCollector::SecurityEventRuler> rulers;
            rulers.emplace_back(ruler);
            const std::string eventGroup = fdp.ConsumeRandomLengthString();
            sptr<OHOS::IRemoteObject> obj(new (std::nothrow) OHOS::MockRemoteObject());
            g_service.QuerySecurityEvent(rulers, obj, eventGroup);
            break;
        }
        case 7: {
            int64_t eventId = fdp.ConsumeIntegral<int64_t>();
            const std::string string = fdp.ConsumeRandomLengthString();
            Security::SecurityCollector::Event event{eventId, string, string, string};
            Security::SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{event};
            sptr<OHOS::IRemoteObject> obj(new (std::nothrow) OHOS::MockRemoteObject());
            g_service.CollectorStart(subscribeInfo, obj);
            break;
        }
        case 8: {
            int64_t eventId = fdp.ConsumeIntegral<int64_t>();
            const std::string string = fdp.ConsumeRandomLengthString();
            Security::SecurityCollector::Event event{eventId, string, string, string};
            Security::SecurityCollector::SecurityCollectorSubscribeInfo subscribeInfo{event};
            sptr<OHOS::IRemoteObject> obj(new (std::nothrow) OHOS::MockRemoteObject());
            g_service.CollectorStop(subscribeInfo, obj);
            break;
        }
        case 9: {
            int64_t fd = fdp.ConsumeIntegral<int32_t>();
            const std::string name = fdp.ConsumeRandomLengthString();
            g_service.ConfigUpdate(fd, name);
            break;
        }
        case 10: {
            std::string name = fdp.ConsumeRandomLengthString();
            g_service.QuerySecurityEventConfig(name);
            break;
        }
        case 11: {
            int64_t eventId = fdp.ConsumeIntegral<int64_t>();
            int64_t type = fdp.ConsumeIntegral<int64_t>();
            Security::SecurityGuard::EventMuteFilter info {};
            info.eventId = eventId;
            info.type = type;
            info.mutes.insert(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
            Security::SecurityGuard::SecurityEventFilter filter(info);
            const std::string clientId = fdp.ConsumeRandomLengthString();
            g_service.AddFilter(filter, clientId);
            break;
        }
        case 12: {
            int64_t eventId = fdp.ConsumeIntegral<int64_t>();
            int64_t type = fdp.ConsumeIntegral<int64_t>();
            Security::SecurityGuard::EventMuteFilter info {};
            info.eventId = eventId;
            info.type = type;
            info.mutes.insert(fdp.ConsumeRandomLengthString(MAX_STRING_SIZE));
            Security::SecurityGuard::SecurityEventFilter filter(info);
            const std::string clientId = fdp.ConsumeRandomLengthString();
            g_service.RemoveFilter(filter, clientId);
            break;
        }
        case 13: {
            int64_t eventId = fdp.ConsumeIntegral<int64_t>();
            const std::string clientId = fdp.ConsumeRandomLengthString();
            g_service.Subscribe(eventId, clientId);
            break;
        }
        case 14: {
            int64_t eventId = fdp.ConsumeIntegral<int64_t>();
            const std::string clientId = fdp.ConsumeRandomLengthString();
            g_service.Unsubscribe(eventId, clientId);
            break;
        }
        case 15: {
            const std::string clientId = fdp.ConsumeRandomLengthString();
            const std::string eventGroup = fdp.ConsumeRandomLengthString();
            sptr<OHOS::IRemoteObject> obj(new (std::nothrow) OHOS::MockRemoteObject());
            g_service.CreatClient(clientId, eventGroup, obj);
            break;
        }
        case 16: {
            const std::string clientId = fdp.ConsumeRandomLengthString();
            const std::string eventGroup = fdp.ConsumeRandomLengthString();
            sptr<OHOS::IRemoteObject> obj(new (std::nothrow) OHOS::MockRemoteObject());
            g_service.DestoryClient(clientId, eventGroup);
            break;
        }
        case 17: {
            int32_t systemAbilityId = fdp.ConsumeIntegral<int32_t>();
            const std::string deviceId = fdp.ConsumeRandomLengthString();
            g_service.OnRemoveSystemAbility(systemAbilityId, deviceId);
            break;
        }
        case 18: {
            int64_t eventId = fdp.ConsumeIntegral<int64_t>();
            OHOS::Security::SecurityCollector::SecurityEventRuler ruler{eventId};
            std::vector<OHOS::Security::SecurityCollector::SecurityEventRuler> rulers;
            rulers.emplace_back(ruler);
            const std::string eventGroup = fdp.ConsumeRandomLengthString();
            sptr<OHOS::IRemoteObject> obj(new (std::nothrow) OHOS::MockRemoteObject());
            g_service.QuerySecurityEventById(rulers, obj, eventGroup);
            break;
        }
        case 19: {
            int32_t fd = fdp.ConsumeIntegral<int32_t>();
            int32_t pid = fdp.ConsumeIntegral<int32_t>();
            std::string res {};
            g_service.QueryCodeSignInfoByPath(fd, pid, res);
            break;
        }
        default:
            break;
    }
    return 0;

}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    SetPermission();
    g_service.OnStart();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on date */
    FuzzedDataProvider fdp(data, size);
    FuzzDataCollectManagerService(fdp);
    g_service.OnStop();
    return 0;
}