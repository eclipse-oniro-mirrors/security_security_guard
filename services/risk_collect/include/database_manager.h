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

#ifndef SECURITY_GUARD_DATABASE_MANAGER_H
#define SECURITY_GUARD_DATABASE_MANAGER_H

#include "distributed_kv_data_manager.h"

namespace OHOS::Security::SecurityGuard {
using namespace OHOS::DistributedKv;

class DatabaseManager {
public:
    explicit DatabaseManager(const DistributedKvDataManager &dataManager);
    virtual ~DatabaseManager() = default;
    virtual Status GetSingleKvStore(const Options &options, const AppId &appId, const StoreId &storeId,
        std::shared_ptr<SingleKvStore> &singleKvStore);
    virtual Status CloseKvStore(const AppId &appId, const StoreId &storeId);
    virtual Status CloseKvStore(const AppId &appId, std::shared_ptr<SingleKvStore> &kvStore);
    virtual Status DeleteKvStore(const AppId &appId, const StoreId &storeId);

private:
    DistributedKvDataManager dataManager_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_DATABASE_MANAGER_H