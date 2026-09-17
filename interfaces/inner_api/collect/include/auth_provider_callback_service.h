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

#ifndef SECURITY_GUARD_AUTH_PROVIDER_CALLBACK_SERVICE_H
#define SECURITY_GUARD_AUTH_PROVIDER_CALLBACK_SERVICE_H

#include <functional>
#include <memory>

#include "auth_provider_callback_stub.h"

namespace OHOS::Security::SecurityGuard {
class AuthProviderCallbackService : public AuthProviderCallbackStub {
public:
    AuthProviderCallbackService();
    ~AuthProviderCallbackService() override;
    void RegistCallBack(std::function<void(const std::vector<AuthClientInfo> &clientsInfo)> callback);
    int32_t OnClientsStatusChanged(const std::vector<AuthClientInfo> &clientsInfo) override;
    void ClearCallBack();
private:
    struct CallbackMutex;
    std::function<void(const std::vector<AuthClientInfo> &clientsInfo)> callback_;
    std::unique_ptr<CallbackMutex> mutexes_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_AUTH_PROVIDER_CALLBACK_SERVICE_H
