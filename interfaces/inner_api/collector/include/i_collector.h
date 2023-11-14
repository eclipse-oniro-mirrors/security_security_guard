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

#ifndef SECURITY_COLLECTOR_NOTIFIER_H
#define SECURITY_COLLECTOR_NOTIFIER_H

#include "i_collector_fwk.h"

namespace OHOS::Security::SecurityCollector {
class ICollector {
public:
    virtual int Start(std::shared_ptr<ICollectorFwk> api) = 0;
    virtual int Stop() = 0;
};
} // namespace OHOS::Security::SecurityCollector
#endif // SECURITY_COLLECTOR_NOTIFIER_H