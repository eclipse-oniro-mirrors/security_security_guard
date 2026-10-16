/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef SECURITY_GUARD_ERROR_CODE_H
#define SECURITY_GUARD_ERROR_CODE_H

namespace OHOS::Security::SecurityGuard {
using ErrorCode = enum {
    SUCCESS,                     // operation succeeded
    FAILED,                      // operation failed
    NO_PERMISSION,               // caller has no required permission
    NO_SYSTEMCALL,               // required system call is not available
    STREAM_ERROR,                // stream read or write error
    FILE_ERR,                    // file operation error
    BAD_PARAM,                   // invalid parameter
    JSON_ERR,                    // json parse or serialize error
    NULL_OBJECT,                 // required object is null
    TIME_OUT,                    // operation timed out
    NOT_FOUND,                   // requested resource not found
    TASK_ERR,                    // task dispatch or execute error
    READ_ERR,                    // data read error
    WRITE_ERR,                   // data write error
    DB_CHECK_ERR,                // database check error
    DB_LOAD_ERR,                 // database load error
    DB_OPT_ERR,                  // database operation error
    DB_INFO_ERR,                 // database info error
    DUPLICATE,                   // duplicated resource or request
    API_SUPPORT_ERROR = 801,     // api not supported on this device
    FILTER_UNSUPPORTED = 1005,   // event filter is not supported
    FILTER_EXCEED_LIMIT = 1006,  // event filter exceeds size limit
    CLIENT_EXCEED_PROCESS_LIMIT = 1007, // client session count exceeds process limit
    CLIENT_EXCEED_GLOBAL_LIMIT = 1008,  // client session count exceeds global limit
    FILE_NOT_FOUND = 1011,       // same as ext
    KERNEL_NOT_SUPPORT = 1012,   // kernel does not support this feature
    // AuthProvider 错误码
    AUTH_PROVIDER_INTERNAL_ERROR = 27000001,       // Provider 内部错误
    AUTH_PROVIDER_EXCEED_PROCESS_LIMIT = 27000002, // Provider 进程会话超限
    AUTH_PROVIDER_EXCEED_GLOBAL_LIMIT = 27000003,  // Provider 全局会话超限
    AUTH_REQUEST_EXCEED_LIMIT = 27000004,          // RequestAuthResult 请求超过上限
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_ERROR_CODE_H
