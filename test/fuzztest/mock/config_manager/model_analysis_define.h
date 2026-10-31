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
    constexpr const char* MODEL_CFG_KEY = "modelcfg";
    constexpr const char* THREAT_CFG_KEY = "threatcfg";
    constexpr const char* EVENT_CFG_KEY = "eventcfg";
    constexpr const char* DATA_MGR_CFG_KEY = "datamgrcfg";

    // model config key
    constexpr const char* MODEL_CFG_MODEL_ID_KEY = "modelId";
    constexpr const char* MODEL_CFG_PATH_KEY = "path";
    constexpr const char* MODEL_CFG_FORMAT_KEY = "format";
    constexpr const char* MODEL_CFG_START_MODE_KEY = "start-mode";
    constexpr const char* MODEL_CFG_PRELOAD_KEY = "preload";
    constexpr const char* MODEL_CFG_EVENT_LIST_KEY = "eventList";
    constexpr const char* MODEL_CFG_PERMISSIONS_KEY = "permissions";
    constexpr const char* MODEL_CFG_DB_TABLE_KEY = "db_table";
    constexpr const char* MODEL_CFG_RUNNING_CNTL_KEY = "running_cntl";
    constexpr const char* MODEL_CFG_CALLER_KEY = "caller";
    constexpr const char* MODEL_CFG_TYPE_KEY = "type";
    constexpr const char* MODEL_CFG_BUILD_IN_CFG_KEY = "buildInDetectionCfg";
    constexpr const char* MODEL_CFG_APP_DETECTION_CFG_KEY = "appDetectionCfg";

    // threat config key
    constexpr const char* THREAT_CFG_THREAT_ID_KEY = "threatId";
    constexpr const char* THREAT_CFG_THREAT_NAME_KEY = "threatName";
    constexpr const char* THREAT_CFG_VERSION_KEY = "version";
    constexpr const char* THREAT_CFG_EVENT_LIST_KEY = "eventList";
    constexpr const char* THREAT_CFG_COMPUTE_MODEL_KEY = "computeModel";

    // event config key
    constexpr const char* EVENT_CFG_EVENT_ID_KEY = "eventId";
    constexpr const char* EVENT_CFG_EVENT_NAME_KEY = "eventName";
    constexpr const char* EVENT_CFG_VERSION_KEY = "version";
    constexpr const char* EVENT_CFG_EVENT_TYPE_KEY = "eventType";
    constexpr const char* EVENT_CFG_COLLECT_ON_START_KEY = "collectOnStart";
    constexpr const char* EVENT_CFG_DATA_SENSITIVITY_LEVEL_KEY = "dataSensitivityLevel";
    constexpr const char* EVENT_CFG_DISCARD_EVENT_WHITELIST_KEY = "discardEventWhiteList";
    constexpr const char* EVENT_CFG_STORAGE_RAM_NUM_KEY = "storageRamNums";
    constexpr const char* EVENT_CFG_STORAGE_ROM_NUM_KEY = "storageRomNums";
    constexpr const char* EVENT_CFG_STORAGE_TIME_KEY = "storageTime";
    constexpr const char* EVENT_CFG_OWNER_KEY = "owner";
    constexpr const char* EVENT_CFG_SOURCE_KEY = "source";
    constexpr const char* EVENT_CFG_DB_TABLE_KEY = "db_table";
    constexpr const char* EVENT_CFG_USER_ID_KEY = "userId";
    constexpr const char* EVENT_CFG_DEVICE_ID_KEY = "deviceId";
    constexpr const char* EVENT_CFG_PROG_KEY = "prog";
    constexpr const char* EVENT_CFG_BATCH_UPLOAD_KEY = "isBatchUpload";
    constexpr const char* EVENT_CFG_IS_STICKY_KEY = "isSticky";
    constexpr const char* EVENT_CFG_OLD_EVENT_ID_KEY = "oldEventId";
    constexpr const char* EVENT_CFG_SERVICE_ID_KEY = "serviceId";
    // date manager key
    constexpr const char* DATA_MGR_DEVICE_ROM_KEY = "deviceRom";
    constexpr const char* DATA_MGR_DEVICE_RAM_KEY = "deviceRam";
    constexpr const char* DATA_MGR_EVENT_MAX_ROM_NUM_KEY = "eventMaxRamNum";
    constexpr const char* DATA_MGR_EVENT_MAX_RAM_NUM_KEY = "eventMaxRomNum";

    // event date key
    constexpr const char* EVENT_DATA_EVENT_ID_KEY = "eventId";
    constexpr const char* EVENT_DATA_VERSION_KEY = "version";
    constexpr const char* EVENT_DATA_DATE_KEY = "date";
    constexpr const char* EVENT_DATA_EVENT_CONTENT_KEY = "eventContent";

    // event content key
    constexpr const char* EVENT_CONTENT_STATUS_KEY = "status";
    constexpr const char* EVENT_CONTENT_CRED_KEY = "cred";
    constexpr const char* EVENT_CONTENT_EXTRA_KEY = "extra";
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_MODEL_ANALYSIS_DEFINE_H
