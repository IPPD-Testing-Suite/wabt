// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstddef>
#include <cstdint>

#include "wabt/leb128.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const uint8_t* end = data + size;
  uint32_t val32 = 0;
  uint64_t val64 = 0;
  wabt::ReadU32Leb128(data, end, &val32);
  wabt::ReadU64Leb128(data, end, &val64);
  wabt::ReadS32Leb128(data, end, &val32);
  wabt::ReadS64Leb128(data, end, &val64);
  return 0;
}
