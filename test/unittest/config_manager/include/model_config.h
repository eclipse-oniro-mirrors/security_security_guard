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

#ifndef SECURITY_GUARD_MODEL_CONFIG_H
#define SECURITY_GUARD_MODEL_CONFIG_H

#include "nlohmann/json.hpp"

#include "base_config.h"
#include "i_model_info.h"

namespace OHOS::Security::SecurityGuard {
class ModelConfig : public BaseConfig {
public:
    ModelConfig() = default;
    ~ModelConfig() override = default;
    bool Load(int mode) override;
    bool Parse() override;
    bool Update() override;

private:
    static bool ParseModelConfig(std::vector<ModelCfg> &configs, nlohmann::json &jsonObj);
    static void CacheModelConfig(const std::vector<ModelCfg> &configs);
};
} // OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_MODEL_CONFIG_H
