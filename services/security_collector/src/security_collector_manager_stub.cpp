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

#include "security_collector_manager_stub.h"

#include "security_collector_define.h"
#include "security_collector_log.h"
namespace OHOS::Security::SecurityCollector {

int32_t SecurityCollectorManagerStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    LOGD("%{public}s", __func__);
    do {
        if (ISecurityCollectorManager::GetDescriptor() != data.ReadInterfaceToken()) {
            break;
        }

        switch (code) {
            case CMD_COLLECTOR_SUBCRIBE: {
                return HandleSubscribeCmd(data, reply);
            }
            case CMD_COLLECTOR_UNSUBCRIBE: {
                return HandleUnsubscribeCmd(data, reply);
            }
            case CMD_COLLECTOR_START: {
                return HandleStartCmd(data, reply);
            }
            case CMD_COLLECTOR_STOP: {
                return HandleStopCmd(data, reply);
            }
            case CMD_SECURITY_EVENT_QUERY: {
                return HandleSecurityEventQueryCmd(data, reply);
            }
            default: {
                break;
            }
        }
    } while (false);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t SecurityCollectorManagerStub::HandleSubscribeCmd(MessageParcel &data, MessageParcel &reply)
{
    LOGI("%{public}s", __func__);
    uint32_t expected = sizeof(uint64_t);
    uint32_t actual = data.GetReadableBytes();
    if (actual <= expected) {
        LOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }

    std::unique_ptr<SecurityCollectorSubscribeInfo> info(data.ReadParcelable<SecurityCollectorSubscribeInfo>());
    if (!info) {
        LOGE("failed to read parcelable for subscribeInfo");
        return BAD_PARAM;
    }

    auto callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        LOGE("callback is nullptr");
        return BAD_PARAM;
    }
    int32_t ret = Subscribe(*info, callback);
    reply.WriteInt32(ret);
    return ret;
}

int32_t SecurityCollectorManagerStub::HandleUnsubscribeCmd(MessageParcel &data, MessageParcel &reply)
{
    LOGI("%{public}s", __func__);
    uint32_t expected = sizeof(uint64_t);
    uint32_t actual = data.GetReadableBytes();
    if (actual <= expected) {
        LOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }

    auto callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        LOGE("callback is nullptr");
        return BAD_PARAM;
    }

    int32_t ret = Unsubscribe(callback);
    reply.WriteInt32(ret);
    return ret;
}

int32_t SecurityCollectorManagerStub::HandleStartCmd(MessageParcel &data, MessageParcel &reply)
{
    LOGI("in HandleStartCmd");
    uint32_t expected = sizeof(uint64_t);
    uint32_t actual = data.GetReadableBytes();
    if (actual <= expected) {
        LOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }

    std::unique_ptr<SecurityCollectorSubscribeInfo> info(data.ReadParcelable<SecurityCollectorSubscribeInfo>());
    if (!info) {
        LOGE("failed to read parcelable for subscribeInfo");
        return BAD_PARAM;
    }

    auto callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        LOGE("callback is nullptr");
        return BAD_PARAM;
    }
    int32_t ret = CollectorStart(*info, callback);
    reply.WriteInt32(ret);
    return ret;
}

int32_t SecurityCollectorManagerStub::HandleStopCmd(MessageParcel &data, MessageParcel &reply)
{
    LOGI("%{public}s", __func__);
    uint32_t expected = sizeof(uint64_t);
    uint32_t actual = data.GetReadableBytes();
    if (actual <= expected) {
        LOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }

    std::unique_ptr<SecurityCollectorSubscribeInfo> info(data.ReadParcelable<SecurityCollectorSubscribeInfo>());
    if (!info) {
        LOGE("failed to read parcelable for subscribeInfo");
        return BAD_PARAM;
    }

    auto callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        LOGE("callback is nullptr");
        return BAD_PARAM;
    }
    int32_t ret = CollectorStop(*info, callback);
    reply.WriteInt32(ret);
    return ret;
}

int32_t SecurityCollectorManagerStub::HandleSecurityEventQueryCmd(MessageParcel &data, MessageParcel &reply)
{
    LOGD("%{public}s", __func__);
    uint32_t expected = sizeof(uint32_t);
    uint32_t actual = data.GetReadableBytes();
    if (actual <= expected) {
        LOGE("actual length error, value=%{public}u", actual);
        return BAD_PARAM;
    }

    uint32_t size = 0;
    if (!data.ReadUint32(size)) {
        LOGE("failed to get the event size");
        return BAD_PARAM;
    }

    if (size > MAX_QUERY_EVENT_SIZE) {
        LOGE("the ruler size error");
        return BAD_PARAM;
    }
    std::vector<SecurityCollector::SecurityEventRuler> rulers;
    for (uint32_t index = 0; index < size; index++) {
        std::shared_ptr<SecurityCollector::SecurityEventRuler> ruler(
            data.ReadParcelable<SecurityCollector::SecurityEventRuler>());
        if (ruler == nullptr) {
            LOGE("failed read security event");
            return BAD_PARAM;
        }
        rulers.emplace_back(*ruler);
    }

    std::vector<SecurityCollector::SecurityEvent> events;
    int32_t ret = QuerySecurityEvent(rulers, events);
    if (ret != SUCCESS) {
        LOGE("QuerySecurityEvent failed, ret=%{public}d", ret);
        return ret;
    }
    if (!reply.WriteUint32(static_cast<uint32_t>(events.size()))) {
        LOGE("failed to WriteInt32 for parcelable vector size");
        return WRITE_ERR;
    }

    for (const auto &event : events) {
        if (!reply.WriteParcelable(&event)) {
            LOGE("failed to WriteParcelable for parcelable");
            return WRITE_ERR;
        }
    }
    return SUCCESS;
}
}