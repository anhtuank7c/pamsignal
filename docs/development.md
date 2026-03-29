# Development Guide

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

| Suite | File | Tests | Covers |
|-------|------|-------|--------|
| `test_utils` | `tests/test_utils.c` | 27 | PAM message parsing, field extraction, IP validation, sanitization, enum-to-string, timestamp formatting |
| `test_config` | `tests/test_config.c` | 16 | Config defaults, file loading, whitespace trimming, boundary values, error handling, partial configs |

### Writing tests

- Every new function or changed behavior must have corresponding tests.
- Tests go in the matching file: `src/foo.c` → `tests/test_foo.c`.
- Register new test executables in `meson.build` under the `# --- Tests ---` section.
- Use CMocka assertions (`assert_int_equal`, `assert_string_equal`, `assert_null`, etc.).

## Formatting and Linting

```bash
# Auto-format all source files
clang-format -i src/*.c include/*.h tests/*.c

# Check without modifying (CI-friendly)
clang-format --dry-run --Werror src/*.c include/*.h tests/*.c

# Static analysis
clang-tidy src/*.c -- $(pkg-config --cflags libsystemd) -I include
```

Configuration files: `.clang-format`, `.clang-tidy` in the project root.

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

# 5. Graceful shutdown (expect: "shutting down" in journal)
sudo kill $(pgrep pamsignal)
# or Ctrl+C if running in foreground
```

## CLI flags

| Flag | Short | Description |
|------|-------|-------------|
| `--foreground` | `-f` | Run in foreground (don't daemonize) |
| `--config PATH` | `-c PATH` | Use alternative config file path |
