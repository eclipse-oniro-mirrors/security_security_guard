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

#ifndef SECURITY_GUARD_AUTH_STRATEGY_H
#define SECURITY_GUARD_AUTH_STRATEGY_H

#include <cstdint>
namespace OHOS::Security::SecurityGuard {
enum AuthStrategy {
    ALLOW = 0,
    DENY = 1,
    TIMEOUT = 2,
};

constexpr int64_t AUTH_RESULT_TIMEOUT_MS = 400;

} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_STRATEGY_H
