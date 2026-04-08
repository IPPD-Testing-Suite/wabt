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

#include "wabt/literal.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0) return 0;
  const char* s = reinterpret_cast<const char*>(data);
  const char* end = s + size;

  uint32_t bits32 = 0;
  uint64_t bits64 = 0;

  wabt::ParseFloat(wabt::LiteralType::Hexfloat, s, end, &bits32);
  wabt::ParseDouble(wabt::LiteralType::Hexfloat, s, end, &bits64);
  wabt::ParseFloat(wabt::LiteralType::Float, s, end, &bits32);
  wabt::ParseDouble(wabt::LiteralType::Float, s, end, &bits64);
  wabt::ParseFloat(wabt::LiteralType::Nan, s, end, &bits32);
  wabt::ParseDouble(wabt::LiteralType::Nan, s, end, &bits64);

  return 0;
}
