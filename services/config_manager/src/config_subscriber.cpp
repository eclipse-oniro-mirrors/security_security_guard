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

#include "config_subscriber.h"

#include <fstream>
#include <mutex>
#include <future>
#include "ffrt.h"
#include "directory_ex.h"
#include "string_ex.h"

#include "bigdata.h"
#include "event_config.h"
#include "config_define.h"
#include "config_manager.h"
#include "model_config.h"
#include "security_guard_log.h"
#include "security_guard_utils.h"
#include "i_model_info.h"
#include "file_util.h"
#include "json_util.h"
#include "sg_collect_client.h"

namespace OHOS::Security::SecurityGuard {
void ConfigSubscriber::GetUpdateFileDstPath(const std::string &fileName, std::string &dstPath)
{
    std::ios::pos_type maxSize = 1 * 1024 * 1024; // byte
    std::string jsonStr;
    if (!FileUtil::ReadFileToStr("/system/etc/security_guard_update_config.json", maxSize, jsonStr)) {
        SGLOGE("Read Update cfg file error.");
        return;
    }
    cJSON *inJson = cJSON_Parse(jsonStr.c_str());
    if (inJson == nullptr || !cJSON_IsArray(inJson)) {
        SGLOGE("Json Parse Error: inJson is null or not a array.");
        cJSON_Delete(inJson);
        inJson = nullptr;
        return;
    }

    int size = cJSON_GetArraySize(inJson);
    for (int i = 0; i < size; i++) {
        cJSON *item = cJSON_GetArrayItem(inJson, i);
        std::string fileNameStr;
        std::string dstPathStr;
        if (!JsonUtil::GetString(item, "fileName", fileNameStr) || !JsonUtil::GetString(item, "dstPath", dstPathStr)) {
            SGLOGE("Json Parse Error: fileName or dstPath not correct.");
            continue;
        }
        if (fileName == fileNameStr) {
            dstPath = dstPathStr;
            break;
        }
    }
    cJSON_Delete(inJson);
    inJson = nullptr;
}

bool ConfigSubscriber::UpdateConfig(const std::string &file)
{
    ConfigUpdateEvent event{};
    bool isSuccess = false;
    if (file == CONFIG_CACHE_FILES[EVENT_CFG_INDEX]) {
        isSuccess = ConfigManager::UpdateConfig<EventConfig>();
    } else if (file == CONFIG_CACHE_FILES[MODEL_CFG_INDEX]) {
        isSuccess = ConfigManager::UpdateConfig<ModelConfig>();
    }

    std::string dstPath = file;
    if (file != CONFIG_CACHE_FILES[EVENT_CFG_INDEX] && file != CONFIG_CACHE_FILES[MODEL_CFG_INDEX]) {
        GetUpdateFileDstPath(file, dstPath);
        if (!dstPath.empty()) {
            SGLOGI("UpdateConfig, tmp path=%{private}s, dstPath=%{private}s.", file.c_str(), dstPath.c_str());
            isSuccess = SecurityGuardUtils::CopyFile(file, dstPath);
        }
    }

    event.path = file;
    event.time = SecurityGuardUtils::GetDate();
    event.ret = isSuccess ? SUCCESS : FAILED;
    SGLOGD("file path=%{private}s, TIME=%{public}s, ret=%{public}d", event.path.c_str(), event.time.c_str(), event.ret);
    BigData::ReportConfigUpdateEvent(event);
    if (isSuccess) {
        std::string name;
        size_t lastSlashPos = dstPath.find_last_of('/');
        if (lastSlashPos != std::string::npos) {
            name = dstPath.substr(lastSlashPos + 1);
        }
        std::string content = R"({"path":")" + dstPath + R"(", "name":")" + name + R"("})";
        auto task = [content] {
            auto info = std::make_shared<EventInfo>(0xAB000004, "1.0", content);
            int32_t ret = SecurityGuard::NativeDataCollectKit::ReportSecurityInfo(info);
            if (ret != SUCCESS) {
                SGLOGE("ReportSecurityEvent Error %{public}d", ret);
            }
        };
        auto thread = std::thread(task);
        thread.join();
    }
    if (!RemoveFile(file)) {
        SGLOGE("remove file error, %{public}s", strerror(errno));
    }
    return isSuccess;
}
}  // namespace OHOS::Security::SecurityGuard
