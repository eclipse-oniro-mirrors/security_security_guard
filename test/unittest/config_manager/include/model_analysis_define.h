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

#ifndef SECURITY_GUARD_MODEL_ANALYSIS_DEFINE_H
#define SECURITY_GUARD_MODEL_ANALYSIS_DEFINE_H

#include <string>

namespace OHOS::Security::SecurityGuard {
    const std::string MODEL_CFG_KEY = "modelcfg";
    const std::string THREAT_CFG_KEY = "threatcfg";
    const std::string EVENT_CFG_KEY = "eventcfg";
    const std::string DATA_MGR_CFG_KEY = "datamgrcfg";

    // model config key
    const std::string MODEL_CFG_MODEL_ID_KEY = "modelId";
    const std::string MODEL_CFG_PATH_KEY = "path";
    const std::string MODEL_CFG_FORMAT_KEY = "format";
    const std::string MODEL_CFG_START_MODE_KEY = "start-mode";
    const std::string MODEL_CFG_PRELOAD_KEY = "preload";
    const std::string MODEL_CFG_EVENT_LIST_KEY = "eventList";
    const std::string MODEL_CFG_PERMISSIONS_KEY = "permissions";
    const std::string MODEL_CFG_DB_TABLE_KEY = "db_table";
    const std::string MODEL_CFG_RUNNING_CNTL_KEY = "running_cntl";
    const std::string MODEL_CFG_CALLER_KEY = "caller";
    const std::string MODEL_CFG_TYPE_KEY = "type";
    const std::string MODEL_CFG_BUILD_IN_CFG_KEY = "buildInDetectionCfg";
    const std::string MODEL_CFG_APP_DETECTION_CFG_KEY = "appDetectionCfg";

    // threat config key
    const std::string THREAT_CFG_THREAT_ID_KEY = "threatId";
    const std::string THREAT_CFG_THREAT_NAME_KEY = "threatName";
    const std::string THREAT_CFG_VERSION_KEY = "version";
    const std::string THREAT_CFG_EVENT_LIST_KEY = "eventList";
    const std::string THREAT_CFG_COMPUTE_MODEL_KEY = "computeModel";

    // event config key
    const std::string EVENT_CFG_EVENT_ID_KEY = "eventId";
    const std::string EVENT_CFG_EVENT_NAME_KEY = "eventName";
    const std::string EVENT_CFG_VERSION_KEY = "version";
    const std::string EVENT_CFG_EVENT_TYPE_KEY = "eventType";
    constexpr const char* EVENT_CFG_COLLECT_ON_START_KEY = "collectOnStart";
    const std::string EVENT_CFG_DATA_SENSITIVITY_LEVEL_KEY = "dataSensitivityLevel";
    const std::string EVENT_CFG_DISCARD_EVENT_WHITELIST_KEY = "discardEventWhiteList";
    const std::string EVENT_CFG_STORAGE_RAM_NUM_KEY = "storageRamNums";
    const std::string EVENT_CFG_STORAGE_ROM_NUM_KEY = "storageRomNums";
    const std::string EVENT_CFG_STORAGE_TIME_KEY = "storageTime";
    const std::string EVENT_CFG_OWNER_KEY = "owner";
    const std::string EVENT_CFG_SOURCE_KEY = "source";
    const std::string EVENT_CFG_DB_TABLE_KEY = "db_table";
    const std::string EVENT_CFG_USER_ID_KEY = "userId";
    const std::string EVENT_CFG_DEVICE_ID_KEY = "deviceId";
    constexpr const char* EVENT_CFG_PROG_KEY = "prog";
    constexpr const char* EVENT_CFG_BATCH_UPLOAD_KEY = "isBatchUpload";
    constexpr const char* EVENT_CFG_IS_STICKY_KEY = "isSticky";
    constexpr const char* EVENT_CFG_OLD_EVENT_ID_KEY = "oldEventId";
    constexpr const char* EVENT_CFG_SERVICE_ID_KEY = "serviceId";
    // date manager key
    const std::string DATA_MGR_DEVICE_ROM_KEY = "deviceRom";
    const std::string DATA_MGR_DEVICE_RAM_KEY = "deviceRam";
    const std::string DATA_MGR_EVENT_MAX_ROM_NUM_KEY = "eventMaxRamNum";
    const std::string DATA_MGR_EVENT_MAX_RAM_NUM_KEY = "eventMaxRomNum";

    // event date key
    const std::string EVENT_DATA_EVENT_ID_KEY = "eventId";
    const std::string EVENT_DATA_VERSION_KEY = "version";
    const std::string EVENT_DATA_DATE_KEY = "date";
    const std::string EVENT_DATA_EVENT_CONTENT_KEY = "eventContent";

    // event content key
    const std::string EVENT_CONTENT_STATUS_KEY = "status";
    const std::string EVENT_CONTENT_CRED_KEY = "cred";
    const std::string EVENT_CONTENT_EXTRA_KEY = "extra";
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_MODEL_ANALYSIS_DEFINE_H
