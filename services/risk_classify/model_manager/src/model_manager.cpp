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

#include "model_manager.h"

#include <dlfcn.h>

#include "directory_ex.h"
#include "file_ex.h"
#include "config_data_manager.h"
#include "security_guard_log.h"
#include "model_manager_impl.h"
#include "database_manager.h"
#include "security_guard_define.h"

namespace OHOS::Security::SecurityGuard {
std::shared_ptr<IModelManager> ModelManager::modelManagerApi_ = std::make_shared<ModelManagerImpl>();

namespace {
    constexpr const char *PREFIX_MODEL_PATH = "/system/lib64/lib";
    constexpr uint32_t AUDIT_MODEL = 3001000003;
}

void ModelManager::Init()
{
    std::vector<uint32_t> modelIds = ConfigDataManager::GetInstance().GetAllModelIds();
    ModelCfg cfg;
    for (uint32_t modelId : modelIds) {
        bool success = ConfigDataManager::GetInstance().GetModelConfig(modelId, cfg);
        if (!success) {
            continue;
        }
        SGLOGI("modelId is %{public}u, start_mode: %{public}u", modelId, cfg.startMode);
        if (cfg.startMode != START_ON_STARTUP) {
            continue;
        }
        if (cfg.modelId != AUDIT_MODEL) {
            (void) InitModel(modelId);
            continue;
        }
    }
}

// 锁内检查：条目在途使用则复用返回 true；否则卸载既有条目并返回 false（条目不存在亦返回 false）
bool ModelManager::ReuseModelIfInUse(uint32_t modelId)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    auto iter = modelIdApiMap_.find(modelId);
    if (iter == modelIdApiMap_.end() || iter->second == nullptr || iter->second->GetModelApi() == nullptr) {
        return false;
    }
    auto use = modelUseCount_.find(modelId);
    if (use != modelUseCount_.end() && use->second > 0) {
        SGLOGI("model is in use, reuse it, modelId=%{public}u", modelId);
        return true;
    }
    iter->second->GetModelApi()->Release();
    modelIdApiMap_.erase(iter);
    return false;
}

// dlopen/dlsym 加载模型 so 并装配 ModelAttrs，失败返回 nullptr（句柄随 attr 析构关闭）
std::unique_ptr<ModelAttrs> ModelManager::LoadModelLib(uint32_t modelId, const std::string &realPath)
{
    void *handle = dlopen(realPath.c_str(), RTLD_LAZY);
    if (handle == nullptr) {
        SGLOGE("modelId=%{public}u, open failed, reason:%{public}s", modelId, dlerror());
        return nullptr;
    }
    std::unique_ptr<ModelAttrs> attr = std::make_unique<ModelAttrs>();
    attr->SetHandle(handle);
    auto getModelApi = (GetModelApi)dlsym(handle, "GetModelApi");
    if (getModelApi == nullptr) {
        SGLOGE("get model api func is nullptr");
        return nullptr;
    }
    IModel *api = getModelApi();
    if (api == nullptr) {
        SGLOGE("get model api is nullptr");
        return nullptr;
    }
    attr->SetModelApi(api);
    return attr;
}

int32_t ModelManager::InitModel(uint32_t modelId)
{
    if (ReuseModelIfInUse(modelId)) {
        return SUCCESS;
    }
    ModelCfg cfg;
    bool success = ConfigDataManager::GetInstance().GetModelConfig(modelId, cfg);
    if (!success) {
        SGLOGE("the model not support, modelId=%{public}u", modelId);
        return NOT_FOUND;
    }
    std::string realPath;
    if (!PathToRealPath(cfg.path, realPath) || realPath.find(PREFIX_MODEL_PATH) != 0) {
        return FILE_ERR;
    }
    std::unique_ptr<ModelAttrs> attr = LoadModelLib(modelId, realPath);
    if (attr == nullptr) {
        return FAILED;
    }
    int32_t ret = attr->GetModelApi()->Init(modelManagerApi_);
    if (ret != SUCCESS) {
        SGLOGE("model api init failed, ret=%{public}d", ret);
        return ret;
    }
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        modelIdApiMap_[modelId] = std::move(attr);
    }
    SGLOGI("init model success, modelId=%{public}u", modelId);
    return SUCCESS;
}

std::string ModelManager::GetResult(uint32_t modelId, const std::string &param)
{
    std::string result = "unknown";
    ModelCfg config;
    bool success = ConfigDataManager::GetInstance().GetModelConfig(modelId, config);
    if (!success) {
        SGLOGI("GetResult GetModelConfig Failed, ModelId=%{public}u", modelId);
        return result;
    }
    // 在途占位：计数大于 0 期间并发 InitModel/Release 不会卸载条目，关闭初始化与使用之间被抹除的窗口
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        ++modelUseCount_[modelId];
    }
    if (config.startMode == START_ON_DEMAND) {
        if (InitModel(modelId) != SUCCESS) {
            DropModelUse(modelId);
            return result;
        }
    }
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        auto iter = modelIdApiMap_.find(modelId);
        if (iter == modelIdApiMap_.end() || iter->second == nullptr || iter->second->GetModelApi() == nullptr) {
            SGLOGI("the model has not been initialized, begin init, modelId=%{public}u", modelId);
        } else {
            result = iter->second->GetModelApi()->GetResult(modelId, param);
        }
    }
    DropModelUse(modelId);
    if (config.startMode == START_ON_DEMAND) {
        Release(modelId);
    }
    return result;
}

int32_t ModelManager::SubscribeResult(uint32_t modelId, std::shared_ptr<IModelResultListener> listener)
{
    if (listener == nullptr) {
        SGLOGE("listener is null, modelId=%{public}u", modelId);
        return BAD_PARAM;
    }
    // 在途占位：防止初始化与使用之间条目被并发卸载
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        ++modelUseCount_[modelId];
    }
    int32_t ret = InitModel(modelId);
    if (ret != SUCCESS) {
        DropModelUse(modelId);
        return ret;
    }

    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        auto iter = modelIdApiMap_.find(modelId);
        if (iter == modelIdApiMap_.end() || iter->second == nullptr || iter->second->GetModelApi() == nullptr) {
            SGLOGI("the model has not been initialized, modelId=%{public}u", modelId);
            ret = FAILED;
        } else {
            ret = iter->second->GetModelApi()->SubscribeResult(listener);
        }
    }
    DropModelUse(modelId);
    return ret;
}

void ModelManager::Release(uint32_t modelId)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    auto use = modelUseCount_.find(modelId);
    if (use != modelUseCount_.end() && use->second > 0) {
        SGLOGI("model is in use, skip release, modelId=%{public}u", modelId);
        return;
    }
    auto iter = modelIdApiMap_.find(modelId);
    if (iter == modelIdApiMap_.end()) {
        SGLOGI("the model has not been initialized, modelId=%{public}u", modelId);
        return;
    }

    if (iter->second == nullptr || iter->second->GetModelApi() == nullptr) {
        SGLOGI("the model attr is nullptr, modelId=%{public}u", modelId);
        modelIdApiMap_.erase(iter);
        return;
    }

    iter->second->GetModelApi()->Release();
    modelIdApiMap_.erase(iter);
}

void ModelManager::DropModelUse(uint32_t modelId)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    auto use = modelUseCount_.find(modelId);
    if (use == modelUseCount_.end()) {
        return;
    }
    if (--(use->second) == 0) {
        modelUseCount_.erase(use);
    }
}

int32_t ModelManager::StartSecurityModel(uint32_t modelId, const std::string &param)
{
    // 在途占位：防止初始化与使用之间条目被并发卸载
    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        ++modelUseCount_[modelId];
    }
    int32_t ret = InitModel(modelId);
    if (ret != SUCCESS) {
        SGLOGE("InitModel fail, ret=%{public}d, modelId=%{public}u", ret, modelId);
        DropModelUse(modelId);
        return ret;
    }

    {
        std::lock_guard<ffrt::mutex> lock(mutex_);
        auto iter = modelIdApiMap_.find(modelId);
        if (iter == modelIdApiMap_.end() || iter->second == nullptr || iter->second->GetModelApi() == nullptr) {
            SGLOGE("the model has not been initialized, modelId=%{public}u", modelId);
            ret = FAILED;
        } else {
            ret = iter->second->GetModelApi()->StartSecurityModel(modelId, param);
        }
    }
    DropModelUse(modelId);
    return ret;
}
} // namespace OHOS::Security::SecurityGuard
