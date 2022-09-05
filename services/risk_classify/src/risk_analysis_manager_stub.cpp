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

#include "risk_analysis_manager_stub.h"

#include <future>

#include "risk_analysis.h"
#include "risk_analysis_define.h"
#include "risk_analysis_manager_callback_proxy.h"
#include "security_guard_define.h"
#include "security_guard_log.h"
#include "security_model_result.h"

namespace OHOS::Security::SecurityGuard {
namespace {
    constexpr int32_t TIMEOUT_REPLY = 500;
}

int32_t RiskAnalysisManagerStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    SGLOGD("%{public}s", __func__);
    do {
        if (IRiskAnalysisManager::GetDescriptor() != data.ReadInterfaceToken()) {
            SGLOGE("descriptor error");
            break;
        }

        switch (code) {
            case CMD_GET_SECURITY_MODEL_RESULT: {
                return HandleGetSecurityModelResult(data, reply);
            }
            default:
                return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    } while (false);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

ErrorCode RiskAnalysisManagerStub::HandleGetSecurityModelResult(MessageParcel &data, MessageParcel &reply)
{
    SGLOGD("%{public}s", __func__);
    // UDID + MODELID + CALLBACK
    uint32_t expected = sizeof(uint32_t);
    uint32_t actual = data.GetReadableBytes();
    if (expected >= actual) {
        SGLOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }

    std::string devId = data.ReadString();
    uint32_t modelId = data.ReadUint32();
    auto object = data.ReadRemoteObject();
    if (object == nullptr) {
        SGLOGE("object is nullptr");
        return BAD_PARAM;
    }
    auto promise = std::make_shared<std::promise<std::unique_ptr<SecurityModelResult>>>();
    auto future = promise->get_future();
    SecurityModelCallBack func = [cap = std::move(promise)] (std::unique_ptr<SecurityModelResult> &callback) mutable {
        cap->set_value(std::move(callback));
    };
    std::unique_ptr<RiskAnalysis> riskAnalysis = std::make_unique<RiskAnalysis>();
    riskAnalysis->RequestSecurityModelResult(devId, modelId, func);

    std::chrono::milliseconds span(TIMEOUT_REPLY);
    ErrorCode ret;
    std::string result{};
    if (future.wait_for(span) == std::future_status::timeout) {
        SGLOGE("wait for result timeout");
        ret = TIME_OUT;
    } else {
        std::unique_ptr<SecurityModelResult> resultPtr = future.get();
        devId = resultPtr->GetDevId();
        modelId = resultPtr->GetModelId();
        result = resultPtr->GetResult();
        ret =  SUCCESS;
    }
    auto proxy = new (std::nothrow) RiskAnalysisManagerCallbackProxy(object);
    if (proxy == nullptr) {
        return NULL_OBJECT;
    }
    proxy->ResponseSecurityModelResult(devId, modelId, result);
    SGLOGI("get analysis result=%{public}s", result.c_str());
    reply.WriteInt32(ret);
    return ret;
}
}