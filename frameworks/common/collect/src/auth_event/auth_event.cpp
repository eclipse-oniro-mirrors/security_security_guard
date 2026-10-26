/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "auth_event.h"

namespace OHOS::Security::SecurityGuard {
bool AuthEvent::Marshalling(Parcel& parcel) const
{
    if (!parcel.WriteInt64(eventId_)) {
        return false;
    }
    if (!parcel.WriteInt64(seqnum_)) {
        return false;
    }
    if (!parcel.WriteString(content_)) {
        return false;
    }
    if (!parcel.WriteString(metadata_)) {
        return false;
    }
    return true;
}

bool AuthEvent::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt64(eventId_)) {
        return false;
    }
    if (!parcel.ReadInt64(seqnum_)) {
        return false;
    }
    if (!parcel.ReadString(content_)) {
        return false;
    }
    if (!parcel.ReadString(metadata_)) {
        return false;
    }
    return true;
}

AuthEvent* AuthEvent::Unmarshalling(Parcel &parcel)
{
    AuthEvent *event = new (std::nothrow) AuthEvent();
    if (event != nullptr && !event->ReadFromParcel(parcel)) {
        delete event;
        event = nullptr;
    }

    return event;
}
} // namespace OHOS::Security::SecurityGuard
