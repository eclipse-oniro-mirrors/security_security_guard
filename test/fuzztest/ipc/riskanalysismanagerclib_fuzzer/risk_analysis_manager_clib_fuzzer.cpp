/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "risk_analysis_manager_callback_service.h"
#include "risk_analysis_manager_service.h"
#include "security_guard_log.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "accesstoken_kit.h"

using namespace OHOS;
using namespace OHOS::Security::SecurityGuard;
namespace {
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

RiskAnalysisManagerService g_service(RISK_ANALYSIS_MANAGER_SA_ID, true);

void SetPermission()
{
    static const char *permission[] = {
        "ohos.permission.securityguard.REQUEST_SECURITY_MODEL_RESULT",
        "ohos.permission.QUERY_SECURITY_MODEL_RESULT"
    };
    uint64_t tokenId;
    NativeTokenInfoParams infoParams = {
        .dcapsNum = 0,
        .permsNum = 2,
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

extern "C" int FuzzRiskAnalysisFuzzService(FuzzedDataProvider &fdp)
{
    static const int ipccode[] = {0, 1, 2, 3, 4};
    int code = fdp.PickValueInArray(ipccode);
    switch (code) {
        case 0: {
            const std::string devId = fdp.ConsumeRandomLengthString();
            uint32_t modleId = fdp.ConsumeIntegral<uint32_t>();
            const std::string param = fdp.ConsumeRandomLengthString();
            sptr<OHOS::IRemoteObject> obj(new (std::nothrow) OHOS::MockRemoteObject());
            g_service.RequestSecurityModelResult(devId, modleId, param, obj);
            break;
        }
        case 1: {
            uint32_t modleId = fdp.ConsumeIntegral<uint32_t>();
            g_service.SetModelState(modleId, fdp.ConsumeBool());
            break;
        }
        case 2: {
            uint32_t modleId = fdp.ConsumeIntegral<uint32_t>();
            const std::string param = fdp.ConsumeRandomLengthString();
            g_service.StartSecurityModel(modleId, param);
            break;
        }
        case 3: {
            uint32_t systemAbilityId = fdp.ConsumeIntegral<int32_t>();
            const std::string deviceId = fdp.ConsumeRandomLengthString();
            g_service.OnAddSystemAbility(systemAbilityId, deviceId);
            break;
        }
        case 4: {
            uint32_t systemAbilityId = fdp.ConsumeIntegral<int32_t>();
            const std::string deviceId = fdp.ConsumeRandomLengthString();
            g_service.OnRemoveSystemAbility(systemAbilityId, deviceId);
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
    FuzzRiskAnalysisFuzzService(fdp);
    g_service.OnStop();
    return 0;
}
