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

#ifndef SECURITY_GUARD_DATA_COLLECT_MANAGER_SERVICE_IPC_INTERFACE_CODE_H
#define SECURITY_GUARD_DATA_COLLECT_MANAGER_SERVICE_IPC_INTERFACE_CODE_H

#include <cstdint>

/* SAID: 3524 */
namespace OHOS::Security::SecurityGuard {
enum class DataCollectManagerInterfaceCode {
    CMD_DATA_COLLECT = 1,
    CMD_DATA_REQUEST = 2,
    CMD_DATA_SUBSCRIBE = 3,
    CMD_DATA_UNSUBSCRIBE = 4,
    CMD_SECURITY_EVENT_QUERY = 5,
    CMD_SECURITY_COLLECTOR_START = 6,
    CMD_SECURITY_COLLECTOR_STOP = 7,
    CMD_SECURITY_CONFIG_UPDATE = 8,
    CMD_SECURITY_EVENT_CONFIG_QUERY = 9,
    CMD_SECURITY_EVENT_MUTE = 10,
    CMD_SECURITY_EVENT_UNMUTE = 11,
    CMD_SECURITY_EVENT_QUERY_BY_ID = 12,
    // 以下为 AuthEvent 框架接口的登记值（非 wire code）：
    // 3524 的实际 IPC code 由 IDL 生成枚举 DataCollectManagerIdlIpcCode 按方法声明顺序分配。
    // 会话内方法（Subscribe/Unsubscribe/SetAuthResult/Destroy）由独立 AuthEventSession.idl
    // 生成枚举 AuthEventSessionIpcCode 承载，不在此登记。
    CMD_CREAT_AUTH_EVENT_CLIENT = 13,
    CMD_CREATE_AUTH_PROVIDER = 14,
};

enum class AuthEventCallbackInterfaceCode {
    CMD_ON_AUTH_EVENT = 1,
};

enum class AuthProviderCallbackInterfaceCode {
    CMD_ON_CLIENT_STATUS_CHANGED = 1,
};

enum class AuthResultCallbackInterfaceCode {
    CMD_ON_AUTH_RESULT = 1,
};

enum class DataCollectManagerCallbackInterfaceCode {
    CMD_SET_REQUEST_DATA = 1,
    CMD_DATA_SUBSCRIBE_CALLBACK = 2,
};

enum class SecurityEventQueryCallbackInterfaceCode {
    CMD_ON_QUERY = 1,
    CMD_ON_COMPLETE = 2,
    CMD_ON_ERROR = 3,
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_DATA_COLLECT_MANAGER_SERVICE_IPC_INTERFACE_CODE_H