// libFuzzer harness for ps_parse_message().
//
// Build (clang only):
//   CC=clang-21 meson setup -Dfuzz=enabled build-fuzz
//   meson compile -C build-fuzz fuzz_parse_message
//
// Run (uses tests/fuzz/parse_message_corpus/ as seed corpus):
//   ./build-fuzz/fuzz_parse_message tests/fuzz/parse_message_corpus \
//       -max_total_time=60
//
// Build flags include -fsanitize=fuzzer,address,undefined so any memory
// safety bug or UB in the parser is reported with a stack trace and a
// reproducer file.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pam_event.h"
#include "utils.h"

// Cap input size — beyond ~4 KB the journal-supplied MESSAGE field is
// already truncated upstream by ps_process_entry, so spending fuzzer cycles
// on huge inputs only stresses memcpy, not the parser.
#define FUZZ_MAX_INPUT 4096

// NOLINTNEXTLINE(readability-identifier-naming) -- libFuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > FUZZ_MAX_INPUT)
        return 0;

    // ps_parse_message expects a NUL-terminated C string. Copy into a local
    // buffer with a guaranteed terminator.
    char buf[FUZZ_MAX_INPUT + 1];
    memcpy(buf, data, size);
    buf[size] = '\0';

    ps_pam_event_t event;
    ps_parse_message(buf, &event);
    return 0;
}
