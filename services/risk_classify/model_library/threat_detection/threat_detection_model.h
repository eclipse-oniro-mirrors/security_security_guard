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

#ifndef SECURITY_GUARD_THREAT_DETECTION_MODEL_H
#define SECURITY_GUARD_THREAT_DETECTION_MODEL_H

#include "nlohmann/json.hpp"

#include "i_model.h"
#include "i_model_manager.h"
#include "i_db_listener.h"

namespace OHOS::Security::SecurityGuard {
using AuditContent = struct {
    int32_t type;
    int32_t subType;
    std::string caller;
    std::string objectInfo;
    std::string bootTime;
    std::string wallTime;
    std::string outTime;
    std::string sourceInfo;
    std::string targetInfo;
    std::string extra;
};

class ThreatDetectionModel : public IModel {
public:
    ~ThreatDetectionModel() override;
    int32_t Init(std::shared_ptr<IModelManager> api) override;
    std::string GetResult() override;
    int32_t SubscribeResult(std::shared_ptr<IModelResultListener> listener) override;
    void Release() override;

private:
    std::shared_ptr<IModelManager> api_;
    std::shared_ptr<IDbOperate> helper_;
    static std::string GetDate();
    void ParseAccountAndReport(const SecurityGuard::SecEvent &events);
    void GetAccountConetnt(const nlohmann::json &jsonObj, AuditContent &content);

    class DbListener : public IDbListener {
    public:
        DbListener() = default;
        ~DbListener() override = default;
        void OnChange(uint32_t optType, const SecEvent &events) override;

        ThreatDetectionModel *model_;
    };
    std::shared_ptr<DbListener> listener_{};
};
} // OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_THREAT_DETECTION_MODEL_H