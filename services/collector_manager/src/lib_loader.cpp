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

#include "lib_loader.h"

#include <dlfcn.h>
#include <string>

#include "directory_ex.h"
#include "security_collector_log.h"

namespace OHOS::Security::SecurityCollector {
LibLoader::LibLoader(const std::string soPath)
    : m_libPath(soPath)
{
}
 
LibLoader::~LibLoader()
{
}
 
ErrorCode LibLoader::LoadLib()
{
    LOGD("LoadLib start");
    std::string realPath;
    if (!PathToRealPath(m_libPath, realPath) || realPath.find("/system/lib") != 0) {
        LOGE("LoadLib m_libPath error, realPath: %{public}s", realPath.c_str());
        return RET_DLOPEN_LIB_FAIL;
    }
    m_handle = dlopen(realPath.c_str(), RTLD_LAZY);
    if (m_handle == nullptr) {
        LOGE("LoadLib m_handle error");
        return RET_DLOPEN_LIB_FAIL;
    }
    LOGD("dlopen success");
    return SUCCESS;
}
 
void LibLoader::UnLoadLib()
{
    LOGI("UnLoadLib start");
    if (m_handle != nullptr) {
        dlclose(m_handle);
    }
    // should call dlclose(m_handle)
    LOGI("dlclose end");
    m_handle = nullptr;
}

ICollector* LibLoader::CallGetCollector()
{
    LOGD("CallGetCollector start");
    if (m_handle == nullptr) {
        LOGE("lib not found");
        return nullptr;
    }
    typedef ICollector* (*GetCollectorFunc)();
    GetCollectorFunc getCollector = reinterpret_cast<GetCollectorFunc>(dlsym(m_handle, "GetCollector"));
    if (!getCollector) {
        LOGE("Failed to get GetCollector function");
        return nullptr;
    }
    return getCollector();
}
}