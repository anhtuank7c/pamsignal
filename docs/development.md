# Development Guide

> **English** · [Tiếng Việt](vi/development.md)

## Prerequisites

```bash
sudo apt install libsystemd-dev pkg-config build-essential meson ninja-build \
    libcmocka-dev clang-format clang-tidy
```

## Build

```bash
# First time: configure the build directory
meson setup build

# Compile
meson compile -C build
```

## Clean

```bash
rm -rf build
meson setup build
```

## Unit Tests

Unit tests use [CMocka](https://cmocka.org/) and are integrated with the Meson build system.

```bash
# Run all tests
meson test -C build -v

# Run a single test suite
meson test -C build test_utils
meson test -C build test_config
```

### Test suites

| Suite | File | Covers |
|-------|------|--------|
| `test_utils` | `tests/test_utils.c` | PAM message parsing (sshd, sudo, su, login; IPv4/IPv6; session actor), forged-field and log-injection cases, IP and port validation, sanitization, truncation marker, enum-to-string and severity helpers, ISO-8601 timestamps |
| `test_config` | `tests/test_config.c` | Defaults, file loading, whitespace, range limits, unknown keys, `enable_notification_type` tokens, `message_style`, `success_after_fail_threshold`, `trusted_sources` CIDR parsing, channel validators (token shapes, URL scheme/charset, WhatsApp ids), `webhook_auth_header`, mTLS file checks, config-file permission rejection |
| `test_notify` | `tests/test_notify.c` | JSON escaping and invalid UTF-8, webhook JSON for every event type (actor, labels, IPv6), compact and pretty chat text with hostile input, login-after-failures and test-alert payloads, notification-type gating, no-channel and cooldown paths |
| `test_journal_watch` | `tests/test_journal_watch.c` | Brute-force tracker (per-IP and local sudo/su keying, window expiry, eviction), login-after-failures checks, trusted sources still tracked, `_EXE` allowlist (`ps_is_trusted_exe`) |
| `test_integration` | `tests/test_integration.c` | Parse, track and format pipeline end to end: SSH brute force over IPv4 and IPv6, local sudo brute force, interleaved IPs |

### Writing tests

- Every new function or changed behavior must have corresponding tests.
- Tests go in the matching file: `src/foo.c` → `tests/test_foo.c`.
- Register new test executables in `meson.build` under the `# --- Tests ---` section. `test_notify`, `test_journal_watch` and `test_integration` `#include` the `.c` file under test to reach its static functions, so do not also list that source in their `meson.build` entry.
- Use CMocka assertions (`assert_int_equal`, `assert_string_equal`, `assert_null`, etc.).

## Fuzzing

`ps_parse_message` is the parser for adversarial input (system journal
messages), so it has a libFuzzer harness in `tests/fuzz_parse_message.c`
gated on the `fuzz` meson option. Builds require clang because
`-fsanitize=fuzzer` is clang-only; ASan and UBSan are enabled alongside.

```bash
# Configure a separate build directory with fuzzing enabled
CC=clang-21 meson setup -Dfuzz=enabled build-fuzz

# Build the harness
meson compile -C build-fuzz fuzz_parse_message

# Run for 60 seconds. The first positional arg is libFuzzer's working corpus
# (writable: discoveries are saved here); the second is the read-only seed
# corpus. build-fuzz/ is gitignored, so discoveries stay out of the repo.
mkdir -p build-fuzz/corpus
./build-fuzz/fuzz_parse_message build-fuzz/corpus \
    tests/fuzz/parse_message_corpus -max_total_time=60
```

Crashes are written to `crash-<sha1>` in the current directory. Use the
crash file as a regression: `./build-fuzz/fuzz_parse_message crash-<sha1>`
reproduces the failing input. If a discovered corpus entry exercises a
genuinely new code path worth keeping, copy it into
`tests/fuzz/parse_message_corpus/` with a descriptive name.

The `fuzz` option defaults to `disabled`, so the regular `meson setup build`
+ gcc workflow is unaffected.

## Formatting and Linting

```bash
# Auto-format all source files
clang-format -i src/*.c include/*.h tests/*.c

# Check without modifying (CI-friendly)
clang-format --dry-run --Werror src/*.c include/*.h tests/*.c

# Static analysis. Uses build/compile_commands.json, which also points at the
# generated paths.h, so run meson setup build first.
clang-tidy -p build src/*.c tests/*.c
```

Configuration files: `.clang-format`, `.clang-tidy` in the project root.

## Sanitizer build

CI runs every test suite under AddressSanitizer and UndefinedBehaviorSanitizer. To reproduce locally:

```bash
meson setup build-asan -Db_sanitize=address,undefined -Db_lundef=false --buildtype=debugoptimized
meson compile -C build-asan
meson test -C build-asan --print-errorlogs
```

## Continuous integration

| Workflow | Runs on | What it does |
|----------|---------|--------------|
| `.github/workflows/ci.yml` | Push to `main`, pull requests to `main` | `sanitizers`: build and run all test suites with ASAN + UBSAN. `who-did-what`: `shellcheck` plus the `examples/who-did-what/tests/e2e.sh` end-to-end test on a full VM with auditd |
| `.github/workflows/grafana-integration.yml` | Changes under `examples/grafana/` or to `docs/grafana-integration.md` | Starts the Grafana, Loki and Alloy compose stack and runs its verify script |
| `.github/workflows/release-packages.yml` | Published release, or manual run | Checks that `meson.build`, `debian/changelog` and `pamsignal.spec` agree on the version; builds and signs the `.deb` (Ubuntu 24.04 and Focal) and `.rpm` (Fedora, EL9); tests them (see [Supported distributions](distros.md)); publishes the apt/dnf repo |
| `.github/workflows/claude.yml` | Issue or PR comments that mention `@claude` | On-demand Claude Code assistant; there is no automatic review on every PR |

The fuzz harness does not run in CI; run it locally as shown above.

## Editing the diagrams

The diagrams in [architecture.md](architecture.md#diagrams) live in `docs/diagrams/*.drawio.svg`. Each file is both the image the docs show and its own draw.io source, so there is nothing separate to keep in sync.

1. Open the file in [draw.io Desktop](https://github.com/jgraph/drawio-desktop/releases) or the VS Code Draw.io Integration extension, and edit it.
2. Re-export it in place with the same settings, so every diagram stays small, sharp and readable in dark mode:

   ```bash
   drawio -x -f svg --theme light --embed-svg-fonts false -e -b 16 \
       -o docs/diagrams/architecture.drawio.svg docs/diagrams/architecture.drawio.svg
   ```

   - `--embed-svg-fonts false` keeps each file under ~100 KB. With fonts embedded, draw.io adds a PNG fallback for every label and the file grows past 1 MB.
   - `--theme light` stops draw.io from switching colours based on the reader's OS theme, which can differ from GitHub's.
   - `-e` embeds the diagram, which keeps the file editable.
   - The white background is set in the diagram itself (*File → Properties → Background*), so the image reads as a light card on GitHub's dark theme.
3. Labels stay in English in both the English and Vietnamese docs, so there is only one set of diagrams.

## Setup test environment

PAMSignal runs as a dedicated unprivileged user with journal read access (not root).

```bash
# Create a system user for pamsignal (no login shell, no home directory)
sudo useradd -r -s /usr/sbin/nologin pamsignal

# Grant permission to read the systemd journal
sudo usermod -aG systemd-journal pamsignal
```

You also need SSH available locally to generate real login events:

```bash
sudo apt install openssh-server
sudo systemctl enable --now ssh
```

## Run (manual)

```bash
# Foreground mode (Ctrl+C to stop)
sudo -u pamsignal ./build/pamsignal --foreground

# Or as a background daemon
sudo -u pamsignal ./build/pamsignal

# With a custom config file
sudo -u pamsignal ./build/pamsignal -f -c ./pamsignal.conf.example
```

## Stop

```bash
# If running manually as background daemon
sudo kill $(pgrep pamsignal)
```

## End-to-end testing

Start pamsignal and open a second terminal to watch its output:

```bash
journalctl -t pamsignal -f
```

Then in a third terminal, trigger events:

```bash
# 1. Successful SSH login (expect: LOGIN_SUCCESS + SESSION_OPEN)
ssh localhost
# type 'exit' (expect: SESSION_CLOSE)

# 2. Failed SSH login (expect: LOGIN_FAILED)
ssh nonexistent@localhost

# 3. Brute-force detection (expect: BRUTE_FORCE_DETECTED after 5 failures)
for i in $(seq 1 5); do ssh nonexistent@localhost; done

# 4. Sudo session (expect: SESSION_OPEN for sudo)
sudo ls

# 5. Login after failures (expect: LOGIN_AFTER_FAILURES). Fail at least
#    success_after_fail_threshold (default 3) times from one address, then
#    log in from the same address within fail_window_sec (default 300).
ssh localhost   # enter a wrong password 3 times, then reconnect and log in

# 6. Graceful shutdown (expect: "shutting down" in journal)
sudo kill $(pgrep pamsignal)
# or Ctrl+C if running in foreground
```

## CLI flags

| Flag | Short | Description |
|------|-------|-------------|
| `--foreground` | `-f` | Run in foreground (don't daemonize) |
| `--config PATH` | `-c PATH` | Use alternative config file path |
| `--check-config` | `-t` | Validate the config file, print enabled channels, exit (0 = valid). Refuses to run as root |
| `--test-alert` | `-T` | Send a test message to every configured channel and exit (0 = all delivered). Refuses to run as root |
| `--version` | `-V` | Print version and exit |
| `--help` | `-h` | Print usage and exit |

Two scripts automate the manual checks: `test_e2e.sh` runs the freshly built binary as the `pamsignal` user and generates events; `tests/scenario.sh` builds and installs the `.deb` on a Debian/Ubuntu host, then runs sshd and sudo brute-force scenarios against a mock webhook (it changes the host and asks before it starts).
