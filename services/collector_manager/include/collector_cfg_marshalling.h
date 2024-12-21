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

#ifndef COLLECTOR_CFG_MARSHALLING_H
#define COLLECTOR_CFG_MARSHALLING_H

#include <string>
#include <vector>

#include "nlohmann/json.hpp"

#include "security_collector_define.h"

namespace OHOS::Security::SecurityCollector {
    void to_json(nlohmann::json &jsonObj, const ModuleCfgSt &moduleCfgSt);
    void from_json(const nlohmann::json &jsonObj, ModuleCfgSt &moduleCfgSt);
} // namespace OHOS::Security::SecurityCollector

#endif // COLLECTOR_CFG_MARSHALLING_H
