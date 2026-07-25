/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SECURITY_COLLECTOR_MANAGER_SERVICE_IPC_INTERFACE_CODE_H
#define SECURITY_COLLECTOR_MANAGER_SERVICE_IPC_INTERFACE_CODE_H

#include <cstdint>

/* SAID: 3525 */
namespace OHOS::Security::SecurityCollector {
enum class SecurityCollectManagerInterfaceCode {
    CMD_COLLECTOR_SUBCRIBE = 1,
    CMD_COLLECTOR_UNSUBCRIBE = 2,
    CMD_COLLECTOR_START = 3,
    CMD_COLLECTOR_STOP = 4,
    CMD_SECURITY_EVENT_QUERY = 5,
    CMD_SECURITY_EVENT_QUERY_BATCH = 6,
};
enum class SecurityCollectManagerCallbackInterfaceCode {
    CMD_COLLECTOR_CALLBACK = 10,
};
} // namespace OHOS::Security::SecurityCollector

#endif // SECURITY_COLLECTOR_MANAGER_SERVICE_IPC_INTERFACE_CODE_H