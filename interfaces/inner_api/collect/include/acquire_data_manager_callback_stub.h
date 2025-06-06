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

#ifndef SECURITY_GUARD_ACQUIRE_DATA_MANAGER_CALBACK_STUB_H
#define SECURITY_GUARD_ACQUIRE_DATA_MANAGER_CALBACK_STUB_H

#include "i_data_collect_manager.h"
#include "iremote_stub.h"

namespace OHOS::Security::SecurityGuard {
class AcquireDataManagerCallbackStub : public IRemoteStub<IAcquireDataCallback>, public NoCopyable {
public:
    AcquireDataManagerCallbackStub() = default;
    ~AcquireDataManagerCallbackStub() override = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
private:
    int32_t HandleBatchSubscribeCallback(MessageParcel &data, MessageParcel &reply);
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_ACQUIRE_DATA_MANAGER_CALBACK_STUB_H