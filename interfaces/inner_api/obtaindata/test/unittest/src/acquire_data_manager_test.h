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

#ifndef SECURITY_GUARD_ACQUIRE_DATA_MANAGER_TEST_H
#define SECURITY_GUARD_ACQUIRE_DATA_MANAGER_TEST_H

#include <gtest/gtest.h>

#include "security_guard_api.h"
#include "security_guard_define.h"

namespace OHOS::Security::SecurityGuardTest {
class AcquireDataManagerTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;

private:
    static bool isEnforcing_;
};
} // namespace OHOS::Security::SecurityGuardTest

#endif  // SECURITY_GUARD_ACQUIRE_DATA_MANAGER_TEST_H
