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

#ifndef SECURITY_GUARD_AUTH_RESULT_CALLBACK_SERVICE_H
#define SECURITY_GUARD_AUTH_RESULT_CALLBACK_SERVICE_H

#include <functional>
#include <memory>

#include "auth_result_callback_stub.h"

namespace OHOS::Security::SecurityGuard {
// C++ 和 NAPI 通用：包装 std::function<void(const AuthResult&)> 为 IPC 回调对象
// SA 聚合完成后调 OnAuthResult → 触发 std::function → C++ 调用方或 NAPI Promise resolve
class AuthResultCallbackService : public AuthResultCallbackStub {
public:
    AuthResultCallbackService();
    ~AuthResultCallbackService() override;
    void RegistCallBack(std::function<void(const AuthResult &result)> callback);
    int32_t OnAuthResult(const AuthResult &result) override;
    void ClearCallBack();
private:
    struct CallbackMutex;
    std::function<void(const AuthResult &result)> callback_;
    std::unique_ptr<CallbackMutex> mutexes_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_RESULT_CALLBACK_SERVICE_H
