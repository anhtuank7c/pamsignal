# Development Guide

> [English](../development.md) · **Tiếng Việt**

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

| Suite | File | Bao phủ |
|-------|------|--------|
| `test_utils` | `tests/test_utils.c` | PAM message parsing (sshd, sudo, su, login; IPv4/IPv6; session actor), các trường hợp giả mạo field và log injection, kiểm tra IP và port, sanitization, truncation marker, các helper enum-to-string và severity, timestamp ISO-8601 |
| `test_config` | `tests/test_config.c` | Giá trị mặc định, đọc file, whitespace, giới hạn khoảng giá trị, key không xác định, các token của `enable_notification_type`, `message_style`, `success_after_fail_threshold`, parse CIDR của `trusted_sources`, validator của các kênh (hình dạng token, URL scheme/charset, WhatsApp id), `webhook_auth_header`, kiểm tra file mTLS, từ chối quyền file config |
| `test_notify` | `tests/test_notify.c` | JSON escaping và UTF-8 không hợp lệ, webhook JSON cho mọi loại sự kiện (actor, label, IPv6), chat text compact và pretty với đầu vào độc hại, payload login-after-failures và test-alert, lọc theo notification type, các nhánh không có kênh và cooldown |
| `test_journal_watch` | `tests/test_journal_watch.c` | Brute-force tracker (khóa theo IP và theo local sudo/su, hết hạn window, eviction), kiểm tra login-after-failures, trusted source vẫn được theo dõi, `_EXE` allowlist (`ps_is_trusted_exe`) |
| `test_integration` | `tests/test_integration.c` | Toàn bộ pipeline parse, track và format: SSH brute force qua IPv4 và IPv6, local sudo brute force, nhiều IP xen kẽ |

### Viết test

- Mỗi hàm mới hoặc hành vi thay đổi phải có các test tương ứng.
- Test đặt trong file tương ứng: `src/foo.c` → `tests/test_foo.c`.
- Đăng ký test executable mới trong `meson.build` dưới section `# --- Tests ---`. `test_notify`, `test_journal_watch` và `test_integration` `#include` trực tiếp file `.c` được test để truy cập các hàm static, nên đừng liệt kê thêm source đó trong mục `meson.build` của chúng.
- Dùng CMocka assertion (`assert_int_equal`, `assert_string_equal`, `assert_null`, v.v.).

## Fuzzing

`ps_parse_message` là parser cho đầu vào từ đối thủ (thông báo system journal), nên nó có libFuzzer harness trong `tests/fuzz_parse_message.c` được gate bởi meson option `fuzz`. Build yêu cầu clang vì `-fsanitize=fuzzer` chỉ có trên clang; ASan và UBSan được bật cùng.

```bash
# Cấu hình một build directory riêng với fuzzing được bật
CC=clang-21 meson setup -Dfuzz=enabled build-fuzz

# Build harness
meson compile -C build-fuzz fuzz_parse_message

# Chạy trong 60 giây. Đối số vị trí đầu tiên là corpus làm việc của libFuzzer
# (có thể ghi: các phát hiện được lưu ở đây); đối số thứ hai là seed
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

# Phân tích tĩnh. Dùng build/compile_commands.json, file này cũng trỏ tới
# paths.h được sinh ra, nên hãy chạy meson setup build trước.
clang-tidy -p build src/*.c tests/*.c
```

File cấu hình: `.clang-format`, `.clang-tidy` trong thư mục gốc dự án.

## Build với sanitizer

CI chạy mọi test suite dưới AddressSanitizer và UndefinedBehaviorSanitizer. Để tái hiện ở máy local:

```bash
meson setup build-asan -Db_sanitize=address,undefined -Db_lundef=false --buildtype=debugoptimized
meson compile -C build-asan
meson test -C build-asan --print-errorlogs
```

## Continuous integration

| Workflow | Chạy khi | Làm gì |
|----------|---------|--------------|
| `.github/workflows/ci.yml` | Push lên `main`, pull request vào `main` | `sanitizers`: build và chạy mọi test suite với ASAN + UBSAN. `who-did-what`: `shellcheck` cùng bài test end-to-end `examples/who-did-what/tests/e2e.sh` trên một VM đầy đủ có auditd |
| `.github/workflows/grafana-integration.yml` | Thay đổi trong `examples/grafana/` hoặc `docs/grafana-integration.md` | Dựng compose stack Grafana, Loki và Alloy rồi chạy script verify của nó |
| `.github/workflows/release-packages.yml` | Khi publish release, hoặc chạy thủ công | Kiểm tra `meson.build`, `debian/changelog` và `pamsignal.spec` khớp phiên bản; build và ký `.deb` (Ubuntu 24.04 và Focal) và `.rpm` (Fedora, EL9); kiểm thử chúng (xem [Các distro được hỗ trợ](distros.md)); publish apt/dnf repo |
| `.github/workflows/ppa-upload.yml` | Khi publish release, hoặc chạy thủ công | Build source package đã ký và upload lên Launchpad PPA cho Ubuntu 24.04 (`noble`) |
| `.github/workflows/claude.yml` | Comment trong issue hoặc PR có nhắc `@claude` | Trợ lý Claude Code theo yêu cầu; không có review tự động cho mỗi PR |

Fuzz harness không chạy trong CI; hãy chạy ở máy local như hướng dẫn ở trên.

## Chỉnh sửa sơ đồ

Các sơ đồ trong [architecture.md](architecture.md#sơ-đồ) nằm ở `docs/diagrams/*.drawio.svg`. Mỗi file vừa là ảnh hiển thị trong tài liệu, vừa là source draw.io của chính nó, nên không có file nào khác cần giữ đồng bộ.

1. Mở file bằng [draw.io Desktop](https://github.com/jgraph/drawio-desktop/releases) hoặc extension Draw.io Integration của VS Code, rồi chỉnh sửa.
2. Export lại tại chỗ với cùng các tuỳ chọn, để mọi sơ đồ đều nhỏ gọn, sắc nét và đọc được ở dark mode:

   ```bash
   drawio -x -f svg --theme light --embed-svg-fonts false -e -b 16 \
       -o docs/diagrams/architecture.drawio.svg docs/diagrams/architecture.drawio.svg
   ```

   - `--embed-svg-fonts false` giữ mỗi file dưới ~100 KB. Nếu nhúng font, draw.io thêm một ảnh PNG dự phòng cho mỗi nhãn và file phình lên hơn 1 MB.
   - `--theme light` ngăn draw.io đổi màu theo theme hệ điều hành của người đọc, vốn có thể khác với theme của GitHub.
   - `-e` nhúng sơ đồ vào file, nhờ đó file vẫn chỉnh sửa được.
   - Nền trắng được đặt ngay trong sơ đồ (*File → Properties → Background*), nên ảnh hiển thị như một thẻ sáng trên dark theme của GitHub.
3. Nhãn trong sơ đồ giữ bằng tiếng Anh cho cả tài liệu tiếng Anh và tiếng Việt, nên chỉ có một bộ sơ đồ.

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

# 5. Login sau nhiều lần thất bại (kỳ vọng: LOGIN_AFTER_FAILURES). Thất bại ít nhất
#    success_after_fail_threshold (mặc định 3) lần từ cùng một địa chỉ, rồi
#    đăng nhập thành công từ địa chỉ đó trong fail_window_sec (mặc định 300).
ssh localhost   # nhập sai mật khẩu 3 lần, rồi kết nối lại và đăng nhập

# 6. Tắt graceful (kỳ vọng: "shutting down" trong journal)
sudo kill $(pgrep pamsignal)
# hoặc Ctrl+C nếu đang chạy ở foreground
```

## CLI flags

| Flag | Viết tắt | Mô tả |
|------|-------|-------------|
| `--foreground` | `-f` | Chạy ở foreground (không daemonize) |
| `--config PATH` | `-c PATH` | Dùng config file path thay thế |
| `--check-config` | `-t` | Kiểm tra config file, in ra các kênh đang bật rồi thoát (0 = hợp lệ). Từ chối chạy với quyền root |
| `--test-alert` | `-T` | Gửi một tin nhắn thử tới mọi kênh đã cấu hình rồi thoát (0 = gửi được hết). Từ chối chạy với quyền root |
| `--version` | `-V` | In phiên bản rồi thoát |
| `--help` | `-h` | In hướng dẫn sử dụng rồi thoát |

Hai script tự động hóa các bước kiểm tra thủ công: `test_e2e.sh` chạy binary vừa build dưới user `pamsignal` và tạo sự kiện; `tests/scenario.sh` build và cài `.deb` trên một host Debian/Ubuntu, rồi chạy các kịch bản brute-force sshd và sudo với một mock webhook (script này thay đổi host và sẽ hỏi trước khi bắt đầu).
