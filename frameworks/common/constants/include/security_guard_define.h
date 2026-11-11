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

#ifndef SECURITY_GUARD_DEFINE_H
#define SECURITY_GUARD_DEFINE_H

#include <string>

#include "security_guard_error_code.h"

namespace OHOS::Security::SecurityGuard {
using SecurityModel = struct {
    std::string devId;
    uint32_t modelId;
    std::string param;
    std::string result;
};

using ObtainDataEvent = struct {
    int32_t pid;
    std::string time;
    int32_t size;
    std::string extend;
};

using ClassifyEvent = struct {
    int32_t pid;
    std::string time;
    std::string eventInfo;
    std::string status;
    std::string extend;
};

using SgSubscribeEvent = struct {
    int32_t pid;
    std::string time;
    int64_t eventId;
    int32_t ret;
    std::string extend;
};

using SgUnsubscribeEvent = struct {
    int32_t pid;
    std::string time;
    int32_t ret;
    std::string extend;
};

using ConfigUpdateEvent = struct {
    std::string path;
    std::string time;
    int32_t ret;
};

using RequestCondition = struct {
    std::vector<int64_t> riskEvent;
    std::vector<int64_t> auditEvent;
    std::string beginTime;
    std::string endTime;
};

using FileSystemStoreErrMesg = struct {
    std::string operation;
    std::string fileName;
    std::string mesg;
};

using ResultCallback = std::function<int32_t (const std::string &devId, uint32_t modelId, const std::string &result)>;

const size_t MAX_QUERY_EVENT_SIZE = 1000;
const size_t MAX_API_INSTACNE_SIZE = 1000;

const size_t MAX_AUTH_CLIENT_SIZE = 16;

} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_DEFINE_H
