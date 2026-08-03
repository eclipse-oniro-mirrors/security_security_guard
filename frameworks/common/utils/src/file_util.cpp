/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "security_guard_log.h"
#include "file_util.h"
#include "directory_ex.h"

namespace OHOS::Security::SecurityGuard {
namespace FileUtil {
bool ReadFileToStr(const std::string &fileName, const std::ios::pos_type fileMaxSize, std::string &str)
{
    SGLOGI("Start read file.");
    std::string realPath;
    if (!PathToRealPath(fileName, realPath)) {
        SGLOGE("Check file path failed, fileName: %{private}s", fileName.c_str());
        return false;
    }
    std::ifstream stream(realPath, std::ios::in);
    if (!stream.is_open()) {
        SGLOGE("File stream error.");
        return false;
    }
    stream.seekg(0, std::ios::end);
    std::ios::pos_type len = stream.tellg();
    if (len == 0 || len > fileMaxSize) {
        SGLOGE("File is empty or too large.");
        stream.close();
        return false;
    }
    stream.seekg(0, std::ios_base::beg);
    std::stringstream strStream;
    strStream << stream.rdbuf();
    str = strStream.str();
    stream.close();
    return true;
}
}
} // namespace OHOS::Security::SecurityGuard