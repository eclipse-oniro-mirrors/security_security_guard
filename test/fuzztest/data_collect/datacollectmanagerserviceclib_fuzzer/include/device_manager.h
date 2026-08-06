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

#ifndef SECURITY_GUARD_DEVICE_MANAGER_MOCK_H
#define SECURITY_GUARD_DEVICE_MANAGER_MOCK_H
#include <string>
namespace OHOS::DistributedHardware {
constexpr int32_t DM_MAX_DEVICE_ID_LEN = 96;

typedef struct DmDeviceInfo {
    char deviceId[DM_MAX_DEVICE_ID_LEN];
} DmDeviceInfo;

class DmInitCallback {
public:
    virtual ~DmInitCallback() {};
    virtual void OnRemoteDied() = 0;
};

class DeviceManager {
public:
    static DeviceManager &GetInstance()
    {
        static DeviceManager instance;
        return instance;
    };
    DeviceManager() = default;
    ~DeviceManager() = default;
    int32_t InitDeviceManager(const std::string &pkgName, std::shared_ptr<DmInitCallback> dmInitCallback)
    {
        return 0;
    }
    int32_t UnInitDeviceManager(const std::string &pkgName)
    {
        return 0;
    }
    int32_t GetLocalDeviceInfo(const std::string &pkgName, DmDeviceInfo &deviceInfo)
    {
        return 0;
    }
};
} // OHOS::DistributedHardware

#endif // SECURITY_GUARD_DEVICE_MANAGER_MOCK_H