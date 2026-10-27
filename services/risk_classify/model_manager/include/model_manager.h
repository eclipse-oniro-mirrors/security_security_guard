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

#ifndef SECURITY_GUARD_MODEL_MANAGER_H
#define SECURITY_GUARD_MODEL_MANAGER_H

#include <cstdint>
#include <mutex>
#include <vector>
#include <unordered_map>

#include "singleton.h"
#include "ffrt.h"
#include "i_model_manager.h"
#include "model_attrs.h"
#include "i_model_result_listener.h"

namespace OHOS::Security::SecurityGuard {
class ModelManager : public Singleton<ModelManager> {
public:
    void Init();
    int32_t InitModel(uint32_t modelId);
    std::string GetResult(uint32_t modelId, const std::string &param);
    int32_t SubscribeResult(uint32_t modelId, std::shared_ptr<IModelResultListener> listener);
    void Release(uint32_t modelId);
    int32_t StartSecurityModel(uint32_t modelId, const std::string &param);

private:
    void DropModelUse(uint32_t modelId);
    bool ReuseModelIfInUse(uint32_t modelId);
    std::unique_ptr<ModelAttrs> LoadModelLib(uint32_t modelId, const std::string &realPath);
    ffrt::mutex mutex_;
    std::unordered_map<uint32_t, std::unique_ptr<ModelAttrs>> modelIdApiMap_;
    // 条目在途使用计数（与 mutex_ 同锁）：GetResult/SubscribeResult/StartSecurityModel 进入时占位，
    // 计数大于 0 期间 InitModel 前言与 Release 不得卸载条目，避免在途用户被并发抹除
    std::unordered_map<uint32_t, uint32_t> modelUseCount_;
    static std::shared_ptr<IModelManager> modelManagerApi_;
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_I_MODEL_MANAGER_API_H
