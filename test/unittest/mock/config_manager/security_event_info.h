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

#ifndef SECURITY_EVENT_CONFIG_INFO_H
#define SECURITY_EVENT_CONFIG_INFO_H

#include <string>
#include <vector>
#include <set>
namespace OHOS::Security::SecurityGuard {
using EventCfg = struct {
    int64_t eventId;
    int64_t oldEventId;
    std::string eventName;
    uint32_t version;
    uint32_t eventType;
    uint32_t collectOnStart;
    uint32_t dataSensitivityLevel;
    uint32_t discardEventWhiteList;
    uint32_t storageRamNums;
    uint32_t storageRomNums;
    int32_t storageTime;
    std::vector<std::string> owner;
    uint32_t source;
    std::string dbTable;
    std::string prog;
    uint32_t isBatchUpload;
    uint32_t isSticky;
    std::string serviceId;
};

using EventGroupCfg = struct {
    std::string eventGroupName;
    std::set<int64_t> eventList;
    std::set<std::string> permissionList;
    bool isBatchUpload;
};
}  // namespace OHOS::Security::SecurityGuard

#endif  // SECURITY_EVENT_CONFIG_INFO_H
