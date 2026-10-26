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

#ifndef DATA_COLLECTION_H
#define DATA_COLLECTION_H

#include <fstream>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <string>
#include <sstream>
#include "ffrt.h"
#include "nlohmann/json.hpp"

#include "lib_loader.h"
#include "i_collector_fwk.h"
#include "security_event.h"
#include "security_event_ruler.h"

namespace OHOS::Security::SecurityCollector {

class DataCollection {
public:
    static DataCollection &GetInstance();
    bool StartCollectors(const std::vector<int64_t>& eventIds, std::shared_ptr<ICollectorFwk> api);
    bool StopCollectors(const std::vector<int64_t> &eventIds);
    int SubscribeCollectors(const std::vector<int64_t> &eventIds, std::shared_ptr<ICollectorFwk> api);
    int SubscribeCollectorsBySticky(const std::vector<int64_t> &eventIds, std::shared_ptr<ICollectorFwk> api);
    int UnsubscribeCollectors(const std::vector<int64_t> &eventIds);
    ErrorCode GetCollectorType(int64_t eventId, int32_t &collectorType);
    int32_t QuerySecurityEvent(const std::vector<SecurityEventRuler> &rulers, std::vector<SecurityEvent> &events);
    int32_t QuerySecurityEventBatch(const std::vector<SecurityEventRuler> &rulers,
        std::vector<SecurityEvent> &events, std::vector<int64_t> &failedEventIds);
    void CloseLib();
private:
    DataCollection() = default;
    int LoadCollector(int64_t eventId, std::string path, std::shared_ptr<ICollectorFwk> api);
    // 查询路径私有辅助方法，假设调用方已持有 opMutex_（CloseLib 依赖该约定避免查询期间 dlclose）
    ErrorCode LoadCollector(std::string path, const SecurityEventRuler &ruler, std::vector<SecurityEvent> &events);
    ErrorCode GetCollectorPath(int64_t eventId, std::string& path);
    ErrorCode CheckFileStream(std::ifstream &stream);
    bool IsCollectorStarted(int64_t eventId);
    // 查询路径私有辅助方法，假设调用方已持有 opMutex_
    int LoadAndQueryBySoPath(const std::string &soPath, const std::vector<SecurityEventRuler> &rulers,
        std::vector<SecurityEvent> &events, std::vector<int64_t> &failedEventIds);
    // 以下两个方法假设调用方已持有 opMutex_（供启动失败回滚与公开入口复用，避免重复加锁）
    int UnsubscribeCollectorsLocked(const std::vector<int64_t> &eventIds);
    bool StopCollectorsLocked(const std::vector<int64_t>& eventIds);
    // 以下辅助方法供启停操作内部复用，均假设调用方已持有 opMutex_（测试/fuzz 等单线程场景除外）
    ICollector* GetCollector(int64_t eventId);
    void IncrementSubscribeCount(int64_t eventId);
    bool DecrementSubscribeCount(int64_t eventId);
    void RebindStickyCollector(int64_t eventId, std::shared_ptr<ICollectorFwk> api);
    ffrt::mutex closeLibmutex_;
    // 串行化"加载/启动/查询采集器"与"停止/卸载采集器"整体操作（含 dlopen/dlclose 与采集器代码执行）。
    // eventIdToLoaderMap_/eventIdToSubscribeCount_ 只在本锁串行化的操作内被访问，无需第二把锁。
    // 回调路径（采集器线程 -> ICollectorFwk::OnNotify）不取本锁；本锁永不在持 closeLibmutex_ 时获取，故无锁环。
    ffrt::mutex opMutex_{};
    std::unordered_map<int64_t, LibLoader> eventIdToLoaderMap_;
    std::unordered_map<int64_t, LibLoader> needCloseLibMap_;
    std::unordered_map<int64_t, uint32_t> eventIdToSubscribeCount_;
};
}
#endif // DATA_COLLECTION_H