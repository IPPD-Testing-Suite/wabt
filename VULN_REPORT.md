# WABT Seeded Vulnerability Report

**Library:** WABT (WebAssembly Binary Toolkit) v1.0.40
**Branch:** main-bugs
**Purpose:** Fuzzer evaluation — intentionally introduced vulnerabilities for sanitizer-guided fuzzing research.
**Date:** 2026-04-08

> **Note:** These bugs are NOT present in the upstream WABT codebase.
> They were introduced deliberately to evaluate custom fuzzer effectiveness.

---

## Summary Table

| # | CWE | Type | File (modified line) | Sanitizer | Trigger Input |
|---|-----|------|----------------------|-----------|---------------|
| 1 | CWE-125 | Out-of-Bounds Read | `src/leb128.cc:197` | ASan heap-buffer-overflow | `\x80\x80\x80\x80` (4 bytes) |
| 2 | CWE-190 | Signed Integer Overflow | `src/literal.cc:333` | UBSan signed-integer-overflow | `0x1p+9999999999` |
| 3 | CWE-121 | Stack Buffer Overflow | `src/literal.cc:794` | ASan stack-buffer-overflow | 16 × `\xff` bytes |
| 4 | CWE-125 | Out-of-Bounds Read | `src/utf8.cc:60` | ASan heap-buffer-overflow | `\xc2` (1 byte) |
| 5 | CWE-122 | Heap Buffer Overflow | `src/binary-reader.cc:420` | ASan heap-buffer-overflow | crafted 16-byte wasm binary |

---

## Bug 1 — LEB128 Off-by-One OOB Read

**File:** `src/leb128.cc`, line 197
**Harness:** `fuzzers/leb128_fuzzer.cc`
**Sanitizer:** ASan heap-buffer-overflow (1-byte read past allocated buffer)

### Change

```diff
- } else if (p + 4 < end && (p[4] & 0x80) == 0) {
+ } else if (p + 4 <= end && (p[4] & 0x80) == 0) {
```

### Description

`ReadU32Leb128` reads a variable-length 32-bit integer from a byte buffer `[p, end)`. The
5-byte encoding path is guarded by the condition `p + 4 < end`, which verifies that at least
5 bytes are available before reading `p[4]`. Changing `<` to `<=` makes the guard equivalent
to `p + 5 <= end + 1`, i.e., it passes when only 4 bytes remain (`p + 4 == end`). On the
next line `p[4]` is dereferenced, reading the byte at address `end`, which is one past the
last valid byte of the allocation. The original `<` guard correctly ensured 5 valid bytes;
the off-by-one admits a read of exactly one byte beyond the buffer.

### Trigger Input

```
\x80\x80\x80\x80
```

Four bytes, each with the continuation bit (0x80) set. The parser skips the 1-, 2-, 3-, and
4-byte branches (none have a terminal byte) and enters the 5-byte branch because `p + 4 <=
end` (`p + 4 == end`). It then reads `p[4]` which lies one byte past the end of the 4-byte
allocation, triggering ASan.

### Reproduction

```bash
printf '\x80\x80\x80\x80' | ./leb128_fuzzer
```

---

## Bug 2 — Signed Integer Overflow in Hex-Float Exponent Parsing

**File:** `src/literal.cc`, line 333 (loop body in `FloatParser<T>::ParseHex`)
**Harness:** `fuzzers/literal_fuzzer.cc`
**Sanitizer:** UBSan signed-integer-overflow

### Change

```diff
  exponent = exponent * 10 + digit;
- if (exponent + significand_exponent_add >= Traits::kMaxExp) {
-   break;
- }
```

### Description

`ParseHex` parses the decimal exponent that follows the `p`/`P` character in a hexadecimal
floating-point literal (e.g., `0x1p+1024`). The loop accumulates decimal digits into `int
exponent` with `exponent = exponent * 10 + digit`. The removed guard broke out of the loop
once the exponent exceeded `Traits::kMaxExp` (1024 for double), preventing the accumulator
from growing past a safe range. Without the guard the loop continues for all input digits,
and after nine nines the value `999999999 * 10 + 9 = 9999999999` exceeds `INT_MAX`
(2147483647), causing C++ signed-integer overflow — undefined behaviour detected by UBSan.

### Trigger Input

```
0x1p+9999999999
```

The string is a valid hex-float prefix `0x1p+` followed by ten nines. After nine iterations
`exponent = 999999999`; the tenth multiplication `999999999 * 10` wraps past `INT_MAX`,
firing UBSan's signed-integer-overflow check.

### Reproduction

```bash
printf '0x1p+9999999999' | ./literal_fuzzer
```

---

## Bug 3 — Stack Buffer Overflow in WriteUint128

**File:** `src/literal.cc`, line 794
**Harness:** `fuzzers/uint128_fuzzer.cc`
**Sanitizer:** ASan stack-buffer-overflow

### Change

```diff
- char reversed_buffer[40];
+ char reversed_buffer[10];
```

### Description

`WriteUint128` converts a 128-bit integer to its decimal string representation. It
accumulates digit groups in a stack-allocated `reversed_buffer` before reversing them into
the output. The original size 40 is large enough for any 128-bit decimal value (at most 39
digits). Shrinking the buffer to 10 characters means any input whose decimal representation
exceeds 10 digits will overflow the stack buffer. The `assert` that previously protected
against this is elided in optimised/NDEBUG builds (as used by fuzzer targets), so the
`memcpy` into `reversed_buffer[len]` writes past the end of the stack frame.

### Trigger Input

```
\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff
```

Sixteen 0xff bytes interpreted as a `v128` equal to UINT128\_MAX
(340282366920938463463374607431768211455), which requires 39 decimal characters — far more
than the 10-byte buffer. ASan reports a stack-buffer-overflow on the first write past
`reversed_buffer[9]`.

### Reproduction

```bash
printf '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' | ./uint128_fuzzer
```

---

## Bug 4 — Off-by-One OOB Read in UTF-8 Validator

**File:** `src/utf8.cc`, line 60
**Harness:** `fuzzers/utf8_fuzzer.cc`
**Sanitizer:** ASan heap-buffer-overflow (1-byte read past allocated buffer)

### Change

```diff
- if (p + length > end) {
+ if (p + length - 1 > end) {
```

### Description

`IsValidUtf8` iterates over a byte buffer validating UTF-8 encoding. For each leading byte
it looks up the expected sequence length (`length` = 1–4) and checks `p + length > end`
before reading the continuation bytes. The original check returns `false` whenever the
remaining buffer is shorter than the declared sequence length, preventing any OOB read.
Changing the guard to `p + length - 1 > end` relaxes it by one: for a 2-byte sequence
(`length = 2`) the guard becomes `p + 1 > end`, which passes when exactly one byte remains
(`p + 1 == end`). The case-2 handler then reads the continuation byte at `p[1]` which lies
at address `end`, one byte past the allocation.

### Trigger Input

```
\xc2
```

A single byte `0xc2` is the leading byte of a 2-byte UTF-8 sequence (`length = 2`). With
only 1 byte in the input (`end = p + 1`) the original guard `p + 2 > end` fires and the
function returns safely. The modified guard `p + 1 > end` evaluates `p + 1 > p + 1` which
is false, so execution falls into the `case 2` handler and reads `*p++` where `p` points at
`end`, triggering ASan.

### Reproduction

```bash
printf '\xc2' | ./utf8_fuzzer
```

---

## Bug 5 — Heap Buffer Overflow via Relaxed String Length Check

**File:** `src/binary-reader.cc`, line 420
**Harness:** `fuzzers/binary_reader_str_fuzzer.cc`
**Sanitizer:** ASan heap-buffer-overflow (1-byte read past allocated wasm input buffer)

### Change

```diff
- ERROR_UNLESS(str_len <= read_end_ - state_.offset,
+ ERROR_UNLESS(str_len <= read_end_ - state_.offset + 1,
               "unable to read string: %s", desc);
```

### Description

`BinaryReader::ReadStr` reads a length-prefixed string from the wasm binary stream. After
reading the LEB128-encoded `str_len`, it validates that the declared length does not exceed
the bytes remaining in the current section (`read_end_ - state_.offset`). Incrementing the
right-hand side by 1 allows `str_len` to be exactly one more than the bytes available. The
`string_view` created immediately after points to `str_len` bytes starting at
`state_.data + state_.offset`; when `str_len = remaining + 1`, the last byte of the view
falls at `state_.data + read_end_`, which is one byte past the end of the wasm binary input
buffer. `IsValidUtf8` then reads all `str_len` bytes, triggering ASan on the final byte.

### Trigger Input

```
\x00\x61\x73\x6d\x01\x00\x00\x00\x00\x06\x06\x6e\x61\x6d\x65\x00
```

16-byte crafted wasm binary: magic (`\x00asm`) + version 1 + custom section (type `\x00`,
size 6), where the section-name LEB128 claims length 6 but only 5 content bytes remain in
the section (`\x6e\x61\x6d\x65\x00` = "name\0"). The section is the last in the file so
`read_end_ == state_.size == 16`; reading 6 bytes from offset 11 accesses byte index 16,
past the 16-byte heap allocation.

### Reproduction

```bash
printf '\x00\x61\x73\x6d\x01\x00\x00\x00\x00\x06\x06\x6e\x61\x6d\x65\x00' | ./binary_reader_str_fuzzer
```

---

## Build Instructions

All harnesses use the libFuzzer interface and are compiled against the `wabt-fuzz` static
library built by CMake with `-DBUILD_FUZZ_TOOLS=ON`.

```bash
cd /path/to/wabt

# Step 1: configure and build the fuzz-instrumented wabt library
mkdir -p out/clang/Debug/fuzz && cd out/clang/Debug/fuzz
cmake -G Ninja \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_FUZZ_TOOLS=ON \
  ../../../..
ninja leb128_fuzzer literal_fuzzer uint128_fuzzer utf8_fuzzer binary_reader_str_fuzzer
cd ../../../..

# Step 2: run a specific harness with its seed corpus
./out/clang/Debug/fuzz/leb128_fuzzer             fuzz-in/leb128/           -max_total_time=60
./out/clang/Debug/fuzz/literal_fuzzer            fuzz-in/literal/          -max_total_time=60
./out/clang/Debug/fuzz/uint128_fuzzer            fuzz-in/uint128/          -max_total_time=60
./out/clang/Debug/fuzz/utf8_fuzzer               fuzz-in/utf8/             -max_total_time=60
./out/clang/Debug/fuzz/binary_reader_str_fuzzer  fuzz-in/binary_reader_str/ -max_total_time=60

# Step 3: reproduce a specific crash
printf '\x80\x80\x80\x80'                                                      | ./out/clang/Debug/fuzz/leb128_fuzzer
printf '0x1p+9999999999'                                                       | ./out/clang/Debug/fuzz/literal_fuzzer
printf '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'      | ./out/clang/Debug/fuzz/uint128_fuzzer
printf '\xc2'                                                                  | ./out/clang/Debug/fuzz/utf8_fuzzer
printf '\x00\x61\x73\x6d\x01\x00\x00\x00\x00\x06\x06\x6e\x61\x6d\x65\x00'   | ./out/clang/Debug/fuzz/binary_reader_str_fuzzer
```

Available harnesses:

| Harness | Targets | Seed directory |
|---------|---------|----------------|
| `leb128_fuzzer` | Bug 1 | `fuzz-in/leb128/` |
| `literal_fuzzer` | Bug 2 | `fuzz-in/literal/` |
| `uint128_fuzzer` | Bug 3 | `fuzz-in/uint128/` |
| `utf8_fuzzer` | Bug 4 | `fuzz-in/utf8/` |
| `binary_reader_str_fuzzer` | Bug 5 | `fuzz-in/binary_reader_str/` |

---

## Expected Sanitizer Output

### Bug 1 — ASan heap-buffer-overflow (read)
```
==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x... at pc 0x...
READ of size 1 at 0x... thread T0
    #0 0x... in wabt::ReadU32Leb128(unsigned char const*, unsigned char const*, unsigned int*) src/leb128.cc:197
    #1 0x... in LLVMFuzzerTestOneInput fuzzers/leb128_fuzzer.cc:24
SUMMARY: AddressSanitizer: heap-buffer-overflow src/leb128.cc:197
```

### Bug 2 — UBSan signed-integer-overflow
```
src/literal.cc:333: runtime error: signed integer overflow: 999999999 * 10 cannot be represented in type 'int'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior src/literal.cc:333
```

### Bug 3 — ASan stack-buffer-overflow (write)
```
==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x... at pc 0x...
WRITE of size N at 0x... thread T0
    #0 0x... in wabt::WriteUint128(char*, unsigned long, wabt::v128) src/literal.cc:803
    #1 0x... in LLVMFuzzerTestOneInput fuzzers/uint128_fuzzer.cc:27
SUMMARY: AddressSanitizer: stack-buffer-overflow src/literal.cc:803
```

### Bug 4 — ASan heap-buffer-overflow (read)
```
==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x... at pc 0x...
READ of size 1 at 0x... thread T0
    #0 0x... in wabt::IsValidUtf8(char const*, unsigned long) src/utf8.cc:74
    #1 0x... in LLVMFuzzerTestOneInput fuzzers/utf8_fuzzer.cc:21
SUMMARY: AddressSanitizer: heap-buffer-overflow src/utf8.cc:74
```

### Bug 5 — ASan heap-buffer-overflow (read)
```
==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x... at pc 0x...
READ of size 1 at 0x... thread T0
    #0 0x... in wabt::IsValidUtf8(char const*, unsigned long) src/utf8.cc:57
    #1 0x... in wabt::BinaryReader::ReadStr(...) src/binary-reader.cc:427
    #2 0x... in LLVMFuzzerTestOneInput fuzzers/binary_reader_str_fuzzer.cc:27
SUMMARY: AddressSanitizer: heap-buffer-overflow src/utf8.cc:57
```

---

## Build System Integration

### CMakeLists.txt

New fuzz targets are added at the bottom of `CMakeLists.txt`, guarded by `BUILD_FUZZ_TOOLS`:

```cmake
if(BUILD_FUZZ_TOOLS)
  wabt_executable(NAME leb128_fuzzer             SOURCES fuzzers/leb128_fuzzer.cc             FUZZ)
  wabt_executable(NAME literal_fuzzer            SOURCES fuzzers/literal_fuzzer.cc            FUZZ)
  wabt_executable(NAME uint128_fuzzer            SOURCES fuzzers/uint128_fuzzer.cc            FUZZ)
  wabt_executable(NAME utf8_fuzzer               SOURCES fuzzers/utf8_fuzzer.cc               FUZZ)
  wabt_executable(NAME binary_reader_str_fuzzer  SOURCES fuzzers/binary_reader_str_fuzzer.cc  FUZZ)
endif()
```

### OSS-Fuzz Makefile (illustrative)

```makefile
all: \
  $(OUT)/leb128_fuzzer \
  $(OUT)/leb128_fuzzer_seed_corpus.zip \
  $(OUT)/literal_fuzzer \
  $(OUT)/literal_fuzzer_seed_corpus.zip \
  $(OUT)/uint128_fuzzer \
  $(OUT)/uint128_fuzzer_seed_corpus.zip \
  $(OUT)/utf8_fuzzer \
  $(OUT)/utf8_fuzzer_seed_corpus.zip \
  $(OUT)/binary_reader_str_fuzzer \
  $(OUT)/binary_reader_str_fuzzer_seed_corpus.zip
```

---

## Changelog

### 2026-04-08 — Initial bug injection

Added 5 intentional vulnerabilities across `src/leb128.cc`, `src/literal.cc` (×2),
`src/utf8.cc`, and `src/binary-reader.cc`. Created dedicated fuzzer harnesses in
`fuzzers/` with seed corpora in `fuzz-in/`. Extended `CMakeLists.txt` with
`BUILD_FUZZ_TOOLS`-gated targets for all five new harnesses.

### 2026-04-08 — Reachability confirmed

Verified direct call path from each `LLVMFuzzerTestOneInput` entry point to the
modified line in the library:

| Harness | Call path |
|---------|-----------|
| `leb128_fuzzer` | `LLVMFuzzerTestOneInput` → `wabt::ReadU32Leb128` (leb128.cc:197) |
| `literal_fuzzer` | `LLVMFuzzerTestOneInput` → `ParseFloat`/`ParseDouble` → `FloatParser::Parse` → `ParseHex` (literal.cc:333) |
| `uint128_fuzzer` | `LLVMFuzzerTestOneInput` → `wabt::WriteUint128` (literal.cc:794) |
| `utf8_fuzzer` | `LLVMFuzzerTestOneInput` → `wabt::IsValidUtf8` (utf8.cc:60) |
| `binary_reader_str_fuzzer` | `LLVMFuzzerTestOneInput` → `ReadBinaryIr` → `ReadSections` → `ReadCustomSection`/`ReadImportSection` → `ReadStr` (binary-reader.cc:420) |

### 2026-04-08 — Seed corpora finalised

| Harness | Seed file | Seed bytes |
|---------|-----------|------------|
| `leb128_fuzzer` | `fuzz-in/leb128/seed001` | `80 80 80 80 00` |
| `literal_fuzzer` | `fuzz-in/literal/seed001` | `30 78 31 70 2b 30` (`0x1p+0`) |
| `uint128_fuzzer` | `fuzz-in/uint128/seed001` | `01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00` |
| `utf8_fuzzer` | `fuzz-in/utf8/seed001` | `c3 a9` |
| `binary_reader_str_fuzzer` | `fuzz-in/binary_reader_str/seed001` | `00 61 73 6d 01 00 00 00` |

---

*This report documents intentional research vulnerabilities.
The upstream WABT library does not contain these bugs.*
