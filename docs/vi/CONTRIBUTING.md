# Đóng Góp cho PAMSignal

> 🌐 [English](../../CONTRIBUTING.md) · **Tiếng Việt**

Cảm ơn bạn đã quan tâm. PAMSignal là một C daemon nhỏ với trọng tâm chặt chẽ vào việc phát hiện các sự kiện PAM auth và gửi cảnh báo; phạm vi cố ý hẹp là một phần trong threat model của dự án. Vui lòng đọc [`docs/threat-model.md`](../../docs/threat-model.md) trước khi đề xuất tính năng — đây là tài liệu tham chiếu để xác định liệu một thay đổi có tăng cường một biện pháp giảm thiểu trong phạm vi hay đưa công việc từ ngoài phạm vi vào daemon.

Tài liệu này bao gồm cách thực hiện đóng góp về code, tài liệu và packaging. Đối với:

- **Báo cáo lỗ hổng bảo mật** → [`SECURITY.md`](SECURITY.md). Không tạo GitHub issue công khai cho các báo cáo bảo mật.
- **Báo cáo lỗi không liên quan đến bảo mật** → [mở một bug-report issue](https://github.com/anhtuank7c/pamsignal/issues/new?template=bug_report.yml).
- **Đề xuất tính năng** → [mở một feature-request issue](https://github.com/anhtuank7c/pamsignal/issues/new?template=feature_request.yml) **trước**, trước khi viết code, để chúng ta có thể thảo luận về phạm vi so với threat model.
- **Đặt câu hỏi / thảo luận về cách dùng** → kiểm tra [`README.md`](../../README.md), [`docs/`](../../docs/), và các GitHub Issues hiện có. Nếu câu hỏi của bạn chưa được giải đáp, hãy mở một issue kiểu feature-request và gắn nhãn `question`.

## Bắt Đầu Nhanh

```bash
git clone https://github.com/anhtuank7c/pamsignal.git
cd pamsignal

# Install build deps (Debian/Ubuntu)
sudo apt-get install -y --no-install-recommends \
  meson ninja-build pkg-config gcc \
  libsystemd-dev libcmocka-dev clang-format clang-tidy

# Build + test
meson setup build
meson compile -C build
meson test -C build
```

Để được hướng dẫn build/debug sâu hơn — fuzzing, chạy ASAN local, các pattern introspection với journalctl, đóng gói thành `.deb` / `.rpm` — xem [`docs/development.md`](../../docs/development.md). Để biết chi tiết về systemd unit + sandbox, xem [`docs/deployment.md`](../../docs/deployment.md).

## Quy Trình Branch + Commit

1. Fork và tạo branch từ `main`. Một branch cho mỗi thay đổi logic.
2. Thực hiện thay đổi của bạn. Giữ các commit nhỏ và tập trung — người review phải có thể hiểu từng commit một cách độc lập.
3. Chạy [danh sách kiểm tra pre-commit](#danh-sách-kiểm-tra-pre-commit) bên dưới. **Mọi mục đều bắt buộc để PR được merge.**
4. Push branch của bạn và mở PR đối với `main`. Điền vào PR template.
5. CI chạy ASAN+UBSAN sanitizers trên mọi push đến PR; cả hai phải pass.

### Commit message

Dự án sử dụng [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <imperative subject under 72 chars>

<optional body explaining *why*, not *what*>
```

Các type được sử dụng ở đây:

| Type | Khi nào |
|---|---|
| `feat:` | Tính năng hoặc hành vi mới |
| `fix:` | Sửa lỗi |
| `security:` | Security hardening hoặc sửa lỗ hổng |
| `refactor:` | Tái cấu trúc không thay đổi hành vi |
| `refactor!:` | Tái cấu trúc với breaking behavior change |
| `docs:` | Chỉ tài liệu |
| `chore:` | Build, CI, packaging, tooling, dependencies |
| `test:` | Thêm hoặc cập nhật tests |
| `perf:` | Cải thiện hiệu năng |

Quy tắc:

- Subject dùng **imperative mood** ("add", "fix", "update" — không phải "added", "fixes", "updated").
- Không có dấu chấm ở cuối subject.
- Body giải thích *tại sao* cần thay đổi; diff đã cho thấy *cái gì* thay đổi.
- Tham chiếu issue bằng `#NNN` trong body, không phải subject.
- Sign-off (`Signed-off-by:`) là tùy chọn nhưng được khuyến khích cho các thay đổi đáng kể.

Ví dụ:

```
fix: stop dropping brute-force counter on SIGHUP reload

Reloading the config previously zeroed the in-memory fail_table,
which let an attacker SIGHUP-spam the daemon to reset their per-IP
counter just before crossing the threshold. Preserve the table
across reloads — config changes shouldn't invalidate observed
attack state.

Refs #42
```

## Tiêu Chuẩn Coding

Mã nguồn C tuân theo các quy ước được mã hóa trong `.clang-format` và `.clang-tidy` tại thư mục gốc của repo. Bước kiểm tra pre-commit (bên dưới) chạy cả hai. Cụ thể:

- **Ngôn ngữ**: `gnu17` (đặt trong `meson.build`).
- **Thụt đầu dòng**: 4 khoảng trắng, không dùng tab.
- **Functions**: `snake_case` với tiền tố `ps_` (ví dụ `ps_journal_watch_init`).
- **Globals**: tiền tố `g_` (ví dụ `g_config`).
- **Macros / `#define`**: `UPPER_SNAKE_CASE` với tiền tố `PS_`.
- **Types** (struct và enum): hậu tố `_t` (ví dụ `ps_pam_event_t`, `ps_event_type_t`).
- **Enum constants**: `UPPER_SNAKE_CASE` với tiền tố `PS_` (clang-tidy bắt buộc điều này — thêm enum không có tiền tố sẽ fail lint).
- **Xử lý lỗi**: return code enum (`PS_OK`, `PS_ERR_*`), early return thay vì các nhánh thành công lồng nhau sâu.
- **Logging**: `sd_journal_print()` / `sd_journal_send()`. **Không được** gọi `printf`, `syslog`, hoặc ghi vào stdout/stderr từ các code path production.

Chính sách comment:

- Mặc định **không viết comment**. Các định danh được đặt tên tốt và các function nhỏ nên làm cho *cái gì* rõ ràng.
- Thêm comment khi *tại sao* không rõ ràng: một ràng buộc ẩn, một bất biến tinh tế, một workaround cho một lỗi cụ thể, hành vi sẽ khiến người đọc ngạc nhiên. Bao gồm đủ context để comment còn giá trị theo thời gian — tham chiếu CVE liên quan, phần man-page kernel, hoặc định dạng thông điệp PAM nếu có thể.

## Yêu Cầu Test

**Mọi function mới hoặc hành vi đã thay đổi đều phải có test tương ứng trong `tests/`.** Thêm một parser pattern? Thêm tests cho pattern mới, các pattern hiện có mà nó không nên match, và hành vi truncation/edge-case. Thêm một config key? Thêm tests cho các giá trị hợp lệ, giá trị ngoài phạm vi, và fallback khi thiếu key. Thay đổi brute-force tracker? Thêm tests cho tuple mới của `(event-shape, expected counter state)`.

Các test suite được xây dựng bằng CMocka và nằm cạnh các module nguồn mà chúng bao phủ:

| Suite | Bao phủ |
|---|---|
| `tests/test_utils.c` | parser, helpers (`sanitize_string`, `is_valid_ip`, ECS helpers) |
| `tests/test_config.c` | config-file parsing, validation, permission checks |
| `tests/test_notify.c` | notify dispatch path (smoke tests cho các no-channel path và cooldown) |
| `tests/test_journal_watch.c` | brute-force tracker (#includes file source trực tiếp để drive file-static state) |

Nếu một thay đổi ảnh hưởng đến hành vi parser, hãy mở rộng `tests/fuzz/parse_message_corpus/` với một input đại diện.

## Danh Sách Kiểm Tra Pre-Commit

Chạy các lệnh này theo thứ tự trước khi mở PR. CI workflow chạy ASAN+UBSAN, nhưng mọi thứ khác là kiểm tra local chạy nhanh hơn trên máy của bạn so với phát hiện qua CI thất bại:

```bash
# 1. Format
clang-format -i src/*.c include/*.h tests/*.c

# 2. Lint (must show zero warnings)
clang-tidy -p build src/*.c tests/*.c

# 3. Build (must show zero warnings)
meson compile -C build

# 4. Test (all suites must pass)
meson test -C build

# 5. Optional but recommended: sanitizer build locally
meson setup build-asan -Db_sanitize=address,undefined -Db_lundef=false --buildtype=debugoptimized
meson compile -C build-asan
meson test -C build-asan
```

Sau đó cập nhật [`CHANGELOG.md`](../../CHANGELOG.md) trong mục `## Unreleased`. Dùng `[x]` cho các mục đã hoàn thành trong branch của bạn và `[ ]` cho các follow-up bạn đang để lại cho sau. Nhóm các mục theo subsection phù hợp (`Features`, `Fixes`, `Security`, `Packaging`, `Documentation`, `CI`).

## Code Review

Một maintainer sẽ review PR của bạn. Dự kiến nhận phản hồi trong vài ngày đối với các thay đổi không nhỏ. Chúng tôi cố gắng giữ các review tập trung vào:

1. **Alignment với threat model** — thay đổi có tăng cường một biện pháp phòng thủ trong phạm vi hay mở rộng daemon vào một non-goal? Xem [`docs/threat-model.md`](../../docs/threat-model.md).
2. **Độ đầy đủ của test** — test suite có mã hóa thay đổi để một regression trong tương lai sẽ fail CI không?
3. **Ổn định API** — thay đổi này có đưa vào một config key, journal field, hoặc webhook payload field mà chúng ta sẽ cần hỗ trợ qua các phiên bản không? Các surface công khai được version hóa qua SemVer; các deprecation cần một overlap period (việc retire `PAMSIGNAL_*` trong v0.3.0 là tiền lệ).
4. **Coding style** — được bao phủ bởi clang-format / clang-tidy; chúng tôi sẽ không tranh cãi về style nếu lần chạy pre-commit của bạn sạch.

Reviewer có thể yêu cầu thay đổi; vui lòng phản hồi trên PR thay vì force-push mà không giải thích. Force-push trong khi review là ổn khi giải quyết rõ ràng một comment, nhưng hãy để lại một ghi chú ngắn trên PR thread nói về những gì đã thay đổi.

## Thay Đổi Distribution và Packaging

Packaging đụng đến `meson.build`, `pamsignal.service.in`, `debian/`, và `pamsignal.spec`. Nếu thay đổi của bạn ảnh hưởng đến bất kỳ file nào trong số này:

- Điểm số `systemd-analyze security` của systemd unit **được gated ở CI ở mức 20** trong `.github/workflows/release-packages.yml` (xem job `test-deb`). Không được loại bỏ một directive hardening mà không có lý do threat-model rõ ràng.
- Cả `debian/` và `pamsignal.spec` đều cần cập nhật song song nếu thay đổi ảnh hưởng đến những gì được cài đặt; job CI `Verify version consistency` phát hiện sự chênh lệch phiên bản giữa `meson.build`, `debian/changelog`, và `pamsignal.spec`.
- Block `%changelog` của `pamsignal.spec` được phân tích bởi `rpm` cũ hơn trên EL9; **không** đặt các macro `%xxx` hoặc `%{...}` trong văn bản changelog hay nó sẽ fail build. Viết dưới dạng văn xuôi ("the install section drops..." thay vì "%install drops...").

## Quy Tắc Ứng Xử

Những người đóng góp được kỳ vọng hành xử mang tính xây dựng và tôn trọng lẫn nhau. Người bảo trì có quyền xóa đóng góp hoặc chặn các tài khoản liên tục không làm được điều đó. Nếu bạn trải nghiệm hoặc quan sát hành vi mâu thuẫn với kỳ vọng này, vui lòng gửi email cho người bảo trì tại địa chỉ được liệt kê trong [`SECURITY.md`](SECURITY.md).
