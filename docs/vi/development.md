# Development Guide

> 🌐 [English](../development.md) · **Tiếng Việt**

## Điều kiện tiên quyết

```bash
sudo apt install libsystemd-dev pkg-config build-essential meson ninja-build \
    libcmocka-dev clang-format clang-tidy
```

## Build

```bash
# Lần đầu: cấu hình thư mục build
meson setup build

# Biên dịch
meson compile -C build
```

## Clean

```bash
rm -rf build
meson setup build
```

## Unit Test

Unit test dùng [CMocka](https://cmocka.org/) và được tích hợp với hệ thống build Meson.

```bash
# Chạy tất cả test
meson test -C build -v

# Chạy một test suite đơn lẻ
meson test -C build test_utils
meson test -C build test_config
```

### Các test suite

| Suite | File | Số test | Bao phủ |
|-------|------|-------|--------|
| `test_utils` | `tests/test_utils.c` | 30 | PAM message parsing, field extraction, IP validation, sanitization, enum-to-string, định dạng timestamp ISO-8601, truncation marker |
| `test_config` | `tests/test_config.c` | 32 | Config default, file loading, whitespace trimming, boundary value, error handling, partial config, validator rejection (hình dạng token, URL scheme/charset, WhatsApp id), từ chối file-permission (group/world-writable, symlink) |
| `test_notify` | `tests/test_notify.c` | 3 | Smoke test public dispatch API: no-channels no-op, cooldown handling khi gọi lặp lại |
| `test_journal_watch` | `tests/test_journal_watch.c` | 13 | Brute-force tracker: validation `ps_fail_table_init`, hành vi bộ đếm single/multi-IP, window expiration, threshold breach, cooldown suppression và release theo IP, eviction-by-oldest, bỏ qua IP rỗng |

### Viết test

- Mỗi hàm mới hoặc hành vi thay đổi phải có các test tương ứng.
- Test đặt trong file tương ứng: `src/foo.c` → `tests/test_foo.c`.
- Đăng ký test executable mới trong `meson.build` dưới section `# --- Tests ---`.
- Dùng CMocka assertion (`assert_int_equal`, `assert_string_equal`, `assert_null`, v.v.).

## Fuzzing

`ps_parse_message` là parser cho đầu vào từ đối thủ (thông báo system journal), nên nó có libFuzzer harness trong `tests/fuzz_parse_message.c` được gate bởi meson option `fuzz`. Build yêu cầu clang vì `-fsanitize=fuzzer` chỉ có trên clang; ASan và UBSan được bật cùng.

```bash
# Cấu hình một build directory riêng với fuzzing được bật
CC=clang-21 meson setup -Dfuzz=enabled build-fuzz

# Build harness
meson compile -C build-fuzz fuzz_parse_message

# Chạy trong 60 giây. Đối số vị trí đầu tiên là corpus làm việc của libFuzzer
# (có thể ghi — các phát hiện được lưu ở đây); đối số thứ hai là seed
# corpus read-only. build-fuzz/ được gitignore nên các phát hiện không vào repo.
mkdir -p build-fuzz/corpus
./build-fuzz/fuzz_parse_message build-fuzz/corpus \
    tests/fuzz/parse_message_corpus -max_total_time=60
```

Crash được ghi vào `crash-<sha1>` trong thư mục hiện tại. Dùng file crash để regression: `./build-fuzz/fuzz_parse_message crash-<sha1>` tái hiện đầu vào lỗi. Nếu một mục corpus được khám phá thực thi một code path mới thực sự đáng giữ lại, hãy copy nó vào `tests/fuzz/parse_message_corpus/` với tên mô tả.

Option `fuzz` mặc định là `disabled`, nên quy trình `meson setup build` + gcc thông thường không bị ảnh hưởng.

## Định dạng và Linting

```bash
# Tự động định dạng tất cả file source
clang-format -i src/*.c include/*.h tests/*.c

# Kiểm tra mà không sửa đổi (thân thiện CI)
clang-format --dry-run --Werror src/*.c include/*.h tests/*.c

# Phân tích tĩnh
clang-tidy src/*.c -- $(pkg-config --cflags libsystemd) -I include
```

File cấu hình: `.clang-format`, `.clang-tidy` trong thư mục gốc dự án.

## Thiết lập môi trường test

PAMSignal chạy dưới dạng người dùng không có đặc quyền chuyên dụng với quyền đọc journal (không phải root).

```bash
# Tạo system user cho pamsignal (không có login shell, không có home directory)
sudo useradd -r -s /usr/sbin/nologin pamsignal

# Cấp quyền đọc systemd journal
sudo usermod -aG systemd-journal pamsignal
```

Bạn cũng cần SSH có sẵn cục bộ để tạo các sự kiện đăng nhập thực:

```bash
sudo apt install openssh-server
sudo systemctl enable --now ssh
```

## Chạy (thủ công)

```bash
# Chế độ foreground (Ctrl+C để dừng)
sudo -u pamsignal ./build/pamsignal --foreground

# Hoặc dưới dạng background daemon
sudo -u pamsignal ./build/pamsignal

# Với config file tùy chỉnh
sudo -u pamsignal ./build/pamsignal -f -c ./pamsignal.conf.example
```

## Dừng

```bash
# Nếu đang chạy thủ công dưới dạng background daemon
sudo kill $(pgrep pamsignal)
```

## Kiểm thử end-to-end

Khởi động pamsignal và mở terminal thứ hai để xem đầu ra của nó:

```bash
journalctl -t pamsignal -f
```

Rồi trong terminal thứ ba, kích hoạt các sự kiện:

```bash
# 1. Đăng nhập SSH thành công (kỳ vọng: LOGIN_SUCCESS + SESSION_OPEN)
ssh localhost
# gõ 'exit' (kỳ vọng: SESSION_CLOSE)

# 2. Đăng nhập SSH thất bại (kỳ vọng: LOGIN_FAILED)
ssh nonexistent@localhost

# 3. Phát hiện brute-force (kỳ vọng: BRUTE_FORCE_DETECTED sau 5 lần thất bại)
for i in $(seq 1 5); do ssh nonexistent@localhost; done

# 4. Sudo session (kỳ vọng: SESSION_OPEN cho sudo)
sudo ls

# 5. Tắt graceful (kỳ vọng: "shutting down" trong journal)
sudo kill $(pgrep pamsignal)
# hoặc Ctrl+C nếu đang chạy ở foreground
```

## CLI flags

| Flag | Viết tắt | Mô tả |
|------|-------|-------------|
| `--foreground` | `-f` | Chạy ở foreground (không daemonize) |
| `--config PATH` | `-c PATH` | Dùng config file path thay thế |
