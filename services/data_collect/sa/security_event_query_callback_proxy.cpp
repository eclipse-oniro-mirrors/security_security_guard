/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "security_event_query_callback_proxy.h"

#include "security_guard_define.h"
#include "security_guard_log.h"

namespace OHOS::Security::SecurityGuard {
SecurityEventQueryCallbackProxy::SecurityEventQueryCallbackProxy(const sptr<OHOS::IRemoteObject> &callback)
    : IRemoteProxy<ISecurityEventQueryCallback>(callback)
{
}

void SecurityEventQueryCallbackProxy::OnQuery(const std::vector<SecurityCollector::SecurityEvent> &events)
{
    SGLOGD("start OnQuery");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return;
    }
    if (!data.WriteUint32(events.size())) {
        SGLOGE("failed to WriteInt32 for parcelable vector size");
        return;
    }

    for (const auto &event : events) {
        if (!data.WriteParcelable(&event)) {
            SGLOGE("failed to WriteParcelable for parcelable");
            return;
        }
    }

    MessageOption option = { MessageOption::TF_SYNC };
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SGLOGE("Remote error");
        return;
    }
    remote->SendRequest(ISecurityEventQueryCallback::CMD_ON_QUERY, data, reply, option);
}

void SecurityEventQueryCallbackProxy::OnComplete()
{
    SGLOGI("start OnComplete");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return;
    }

    MessageOption option = { MessageOption::TF_SYNC };
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SGLOGE("Remote error");
        return;
    }
    remote->SendRequest(ISecurityEventQueryCallback::CMD_ON_COMPLETE, data, reply, option);
}

void SecurityEventQueryCallbackProxy::OnError(const std::string &message)
{
    SGLOGI("start OnError");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        return;
    }
    if (!data.WriteString(message)) {
        SGLOGE("failed to WriteString for parcelable vector size");
        return;
    }

    MessageOption option = { MessageOption::TF_SYNC };
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        SGLOGE("Remote error");
        return;
    }
    remote->SendRequest(ISecurityEventQueryCallback::CMD_ON_ERROR, data, reply, option);
}
}