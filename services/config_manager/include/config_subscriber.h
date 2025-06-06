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

#ifndef SECURITY_GUARD_CONFIG_SUBSCRIBER_H
#define SECURITY_GUARD_CONFIG_SUBSCRIBER_H
#include <functional>
#include <string>
#include <mutex>
namespace OHOS::Security::SecurityGuard {
using TimeEventRelatedCallBack = std::function<bool(void)>;
class ConfigSubscriber {
public:
    static bool UpdateConfig(const std::string &file);
    static void GetUpdateFileDstPath(const std::string &fileName, std::string &dstPath);
};
} // OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_CONFIG_SUBSCRIBER_H