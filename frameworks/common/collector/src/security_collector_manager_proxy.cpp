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

#include "security_collector_manager_proxy.h"

#include "security_collector_define.h"
#include "security_collector_log.h"

namespace OHOS::Security::SecurityCollector {
SecurityCollectorManagerProxy::SecurityCollectorManagerProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<ISecurityCollectorManager>(impl)
{
}

int32_t SecurityCollectorManagerProxy::Subscribe(const SecurityCollectorSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &callback)
{
    LOGI("enter SecurityCollectorManagerProxy Subscribe");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOGE("WriteInterfaceToken error");
        return WRITE_ERR;
    }

    if (!data.WriteParcelable(&subscribeInfo)) {
        LOGE("failed to write parcelable for subscribeInfo");
        return WRITE_ERR;
    }

    if (!data.WriteRemoteObject(callback)) {
        LOGE("failed to write remote object for callback");
        return WRITE_ERR;
    }

    MessageOption option = { MessageOption::TF_SYNC };
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOGE("Remote error");
        return NULL_OBJECT;
    }
    int ret = remote->SendRequest(CMD_COLLECTOR_SUBCRIBE, data, reply, option);
    if (ret != ERR_NONE) {
        LOGE("ret=%{public}d", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    LOGD("reply=%{public}d", ret);
    return ret;
}

int32_t SecurityCollectorManagerProxy::Unsubscribe(const sptr<IRemoteObject> &callback)
{
    LOGI("enter SecurityCollectorManagerProxy Unsubscribe");
    MessageParcel data;
    MessageParcel reply;
    
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOGE("WriteInterfaceToken error");
        return WRITE_ERR;
    }

    if (!data.WriteRemoteObject(callback)) {
        LOGE("failed to write remote object for callback");
        return WRITE_ERR;
    }

    MessageOption option = { MessageOption::TF_SYNC };
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOGE("Remote error");
        return NULL_OBJECT;
    }
    int ret = remote->SendRequest(CMD_COLLECTOR_UNSUBCRIBE, data, reply, option);
    if (ret != ERR_NONE) {
        LOGE("ret=%{public}d", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    LOGD("reply=%{public}d", ret);
    return ret;
}

int32_t SecurityCollectorManagerProxy::CollectorStart(const SecurityCollectorSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    LOGI("enter SecurityCollectorManagerProxy CollectorStart");
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOGE("WriteInterfaceToken error");
        return WRITE_ERR;
    }

    if (!data.WriteParcelable(&subscribeInfo)) {
        LOGE("failed to write parcelable for subscribeInfo");
        return WRITE_ERR;
    }
    if (!data.WriteRemoteObject(callback)) {
        LOGE("failed to write remote object for callback");
        return WRITE_ERR;
    }
    MessageOption option = { MessageOption::TF_SYNC };
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOGE("Remote error");
        return NULL_OBJECT;
    }
    int ret = remote->SendRequest(CMD_COLLECTOR_START, data, reply, option);
    if (ret != ERR_NONE) {
        LOGE("ret=%{public}d", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    LOGD("reply=%{public}d", ret);
    return ret;
}

int32_t SecurityCollectorManagerProxy::CollectorStop(const SecurityCollectorSubscribeInfo &subscribeInfo,
    const sptr<IRemoteObject> &callback)
{
    MessageParcel data;
    MessageParcel reply;
    LOGI("enter SecurityCollectorManagerProxy CollectorStop");
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOGE("WriteInterfaceToken error");
        return WRITE_ERR;
    }

    if (!data.WriteParcelable(&subscribeInfo)) {
        LOGE("failed to write parcelable for subscribeInfo");
        return WRITE_ERR;
    }
    if (!data.WriteRemoteObject(callback)) {
        LOGE("failed to write remote object for callback");
        return WRITE_ERR;
    }
    MessageOption option = { MessageOption::TF_SYNC };
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOGE("Remote error");
        return NULL_OBJECT;
    }
    int ret = remote->SendRequest(CMD_COLLECTOR_STOP, data, reply, option);
    if (ret != ERR_NONE) {
        LOGE("ret=%{public}d", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    LOGD("reply=%{public}d", ret);
    return ret;
}

int32_t SecurityCollectorManagerProxy::QuerySecurityEvent(const std::vector<SecurityEventRuler> rulers,
    std::vector<SecurityEvent> &events)
{
    LOGD("enter SecurityCollectorManagerProxy QuerySecurityEvent");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOGE("WriteInterfaceToken error");
        return WRITE_ERR;
    }

    if (!data.WriteUint32(rulers.size())) {
        LOGE("failed to WriteInt32 for parcelable vector size");
        return WRITE_ERR;
    }

    for (const auto &ruler : rulers) {
        if (!data.WriteParcelable(&ruler)) {
            LOGE("failed to WriteParcelable for parcelable");
            return WRITE_ERR;
        }
    }

    MessageOption option = { MessageOption::TF_SYNC };
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOGE("Remote error");
        return NULL_OBJECT;
    }
    int ret = remote->SendRequest(CMD_SECURITY_EVENT_QUERY, data, reply, option);
    if (ret != ERR_NONE) {
        LOGE("ret=%{public}d", ret);
        return ret;
    }

    uint32_t size = 0;
    if (!reply.ReadUint32(size)) {
        LOGE("failed to get the event size");
        return BAD_PARAM;
    }

    if (size > MAX_QUERY_EVENT_SIZE) {
        LOGE("the event size error");
        return BAD_PARAM;
    }
    for (uint32_t index = 0; index < size; index++) {
        std::shared_ptr<SecurityEvent> event(reply.ReadParcelable<SecurityEvent>());
        if (event == nullptr) {
            LOGE("failed read security event");
            return BAD_PARAM;
        }
        events.emplace_back(*event);
    }
    return SUCCESS;
}
}