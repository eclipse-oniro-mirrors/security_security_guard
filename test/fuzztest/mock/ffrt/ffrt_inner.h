/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef TEST_FUZZTEST_MOCK_FFRT_FFRT_INNER_H
#define TEST_FUZZTEST_MOCK_FFRT_FFRT_INNER_H

#include "ffrt.h"
#include <future>

namespace ffrt {
    using future_status = std::future_status;
    template<typename R> using promise = std::promise<R>;
    template<typename R> using future = std::future<R>;
}

#endif  // TEST_FUZZTEST_MOCK_FFRT_FFRT_INNER_H
