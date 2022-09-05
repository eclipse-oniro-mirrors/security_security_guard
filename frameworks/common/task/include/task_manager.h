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

#ifndef SECURITY_GUARD_TASK_MANAGER_H
#define SECURITY_GUARD_TASK_MANAGER_H

#include "base_task.h"

namespace OHOS::Security::SecurityGuard {
class TaskManager {
public:
    ~TaskManager() = default;
    static TaskManager& GetInstance();
    bool PushTask(std::shared_ptr<BaseTask> &task);

private:
    TaskManager();
};
} // namespace OHOS::Security::SecurityGuard

#endif // SECURITY_GUARD_TASK_MANAGER_H