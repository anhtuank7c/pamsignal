# Chính Sách Bảo Mật

> 🌐 [English](../../SECURITY.md) · **Tiếng Việt**

PAMSignal là một daemon giám sát bảo mật. Một lỗ hổng trong chính daemon — vượt qua brute-force tracker, giả mạo cảnh báo, log injection, leo thang đặc quyền, memory corruption — được coi là một lỗi ưu tiên cao. Tài liệu này mô tả cách báo cáo riêng tư và những gì bạn có thể mong đợi sau khi báo cáo.

## Báo Cáo Lỗ Hổng

**Vui lòng không tạo một GitHub issue công khai cho các báo cáo bảo mật.** Báo cáo công khai tạo lợi thế cho kẻ tấn công trước khi bản vá được phát hành.

Sử dụng một trong các kênh riêng tư dưới đây:

1. **Ưu tiên — GitHub Security Advisories.** Mở một advisory riêng tư trên repository:
   <https://github.com/anhtuank7c/pamsignal/security/advisories/new>
   Thread này vẫn riêng tư cho đến khi cả người báo cáo và người bảo trì đồng ý công bố, và việc yêu cầu gán CVE có thể được thực hiện qua cùng một giao diện.

2. **Email dự phòng** nếu GitHub UI không sử dụng được:
   `anhtuank7c@hotmail.com` với tiêu đề bắt đầu bằng `[pamsignal-security]`.
   Mã hóa PGP hiện không bắt buộc, nhưng nếu bạn có thì fingerprint của khóa ký của người bảo trì là `2D2C 828F A6F4 D019 E446  8FBB B106 2235 2862 2F69` (cùng khóa được dùng để ký các package apt + dnf release).

Khi báo cáo, vui lòng bao gồm:

- Phiên bản pamsignal (`pamsignal --version` nếu có, nếu không thì phiên bản package từ `apt show pamsignal` / `dnf info pamsignal`).
- Bạn tái hiện lỗi từ một `.deb`/`.rpm` đã được phát hành hay từ một source build `meson install`.
- Chuỗi sự kiện journal / cấu hình tối giản kích hoạt vấn đề, lý tưởng là một unit-test reproducer hoặc một đoạn trích `journalctl --output=export`.
- Đánh giá của bạn về mức độ nghiêm trọng và các điều kiện tiên quyết để khai thác (người dùng local, cấu hình cụ thể, distro cụ thể, v.v.).

## Lịch Trình Công Bố

- **Xác nhận**: trong vòng 5 ngày làm việc kể từ khi nhận được.
- **Phân loại và đánh giá mức độ nghiêm trọng**: trong vòng 14 ngày. Người bảo trì sẽ chia sẻ đánh giá và đề xuất lịch trình khắc phục lại cho người báo cáo.
- **Công bố có phối hợp**: cửa sổ tiêu chuẩn là **90 ngày** từ khi xác nhận đến khi công bố công khai. Người bảo trì sẽ yêu cầu gia hạn (kèm lý do) cho các vấn đề yêu cầu một bản vá phối hợp upstream hoặc migration phức tạp; người báo cáo có quyền từ chối và tiến hành với lịch trình công bố của riêng họ.
- **Advisory công khai**: được phát hành dưới dạng GitHub Security Advisory + mục trong `CHANGELOG.md` theo release liên quan. Người báo cáo được ghi công trừ khi họ yêu cầu ẩn danh.

## Các Phiên Bản Được Hỗ Trợ

Hai trục:

**Dòng release.** Chỉ dòng release **minor** gần nhất mới nhận được bản vá bảo mật. Các bản vá cho các minor cũ hơn được xem xét từng trường hợp và chỉ khi bản vá rõ ràng trong một dòng — bất kỳ ai chạy project đều nên mong đợi việc nâng cấp lên minor mới nhất để được hỗ trợ bảo mật.

| Phiên bản | Được hỗ trợ |
|---------|-----------|
| `0.3.x` | ✅ |
| `0.2.x` | ❌ (dùng `0.3.x`) |
| `0.1.x` | ❌ |

Đường cài đặt được khuyến nghị là repository apt hoặc dnf đã được ký, được ghi lại trong [`README.md`](README.md#1-cài-đặt); `apt upgrade` / `dnf upgrade` giữ bạn trên dòng được hỗ trợ một cách tự động.

**Hệ điều hành / distro.** Pamsignal chỉ hỗ trợ Linux hiện đại có systemd gốc. Ma trận distro đầy đủ — các distro được kiểm tra trên CI, các distro dự kiến hoạt động với chú thích từng dòng, và các release không được hỗ trợ rõ ràng với lý do kỹ thuật cho mỗi điểm cut-off — nằm trong [`docs/distros.md`](../../docs/distros.md). Một báo cáo lỗ hổng đối với distro Tier 3 sẽ bị đóng với một con trỏ đến tài liệu đó; các lỗ hổng ảnh hưởng đến distro Tier 1 hoặc Tier 2 nằm trong phạm vi xem xét bảo mật theo chính sách này.

## Phạm Vi

Bảng phân tích đầy đủ trong phạm vi / ngoài phạm vi — bao gồm các khả năng của kẻ tấn công mà daemon giả định, ranh giới tin cậy bên trong codebase, và các lựa chọn thiết kế tạo ra tư thế bảo mật hiện tại — nằm trong [`docs/threat-model.md`](../../docs/threat-model.md). Hãy đọc trước khi báo cáo; đặc biệt, phần "Out of scope" ở đó rất toàn diện về các non-goal (compromised journald / libsystemd / curl, root đã có trên host, alert-provider compromise, multi-host correlation, durable alert delivery, admin misconfiguration).

Tóm tắt, đủ cho hầu hết các báo cáo:

**Trong phạm vi.** Các lỗi memory-safety trong `src/`; các lỗi logic trong `ps_parse_message` vượt qua allowlist `_EXE`; các bypass của brute-force tracker; alert-payload injection (JSON-escape escapes, credential leakage vào argv, URL hijack của `curl` child); các đường leo thang đặc quyền từ user `pamsignal`; các bypass của các directive hardening trong systemd unit.

**Ngoài phạm vi.** Các lỗ hổng trong `curl`, `libsystemd`, journald, hoặc bất kỳ nhà cung cấp alert-channel nào; các threat model yêu cầu root trên host được giám sát; admin misconfiguration; giới hạn tốc độ alert-channel / DoS qua lũ sự kiện hợp pháp.

## Các Biện Pháp Hardening Đã Được Triển Khai

Xem xét các biện pháp phòng thủ hiện có trước khi báo cáo giúp tiết kiệm thời gian cho cả hai bên:

- Allowlist `_EXE` trên mọi journal entry (`src/journal_watch.c`): chỉ các entry có đường dẫn thực thi được ghi nhận phân giải thành `sshd`, `sudo`, `su`, `login`, hoặc `systemd-logind` dưới một system prefix mới được xử lý. Các sự kiện giả mạo từ `logger(1)` bị bỏ qua âm thầm.
- Compiler hardening (`meson.build`): `-fstack-protector-strong`, `_FORTIFY_SOURCE=3`, `-fcf-protection=full`, `-fstack-clash-protection`, full RELRO, PIE, separate-code, no-exec-stack.
- Alert dispatch isolation: `fork()` + `execv()` của một `/usr/bin/curl` với đường dẫn tuyệt đối với môi trường đã được `clearenv()`. Webhook URL và bearer token được ghi vào một file `--config` được hỗ trợ bởi `memfd_create()` và truyền qua `/dev/fd/9`; chúng không bao giờ xuất hiện trong argv.
- systemd unit hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, `RestrictNamespaces`, `SystemCallFilter=@system-service ~@privileged @resources`, `CapabilityBoundingSet=` (trống). Có thể xác minh bằng `systemd-analyze security pamsignal.service`.
- Fuzzing liên tục: `tests/fuzz_parse_message.c` là một libFuzzer harness tùy chọn cho `ps_parse_message`. Chạy với `meson setup -Dfuzz=enabled build-fuzz` (yêu cầu clang).

Nếu phát hiện của bạn là một cải tiến dựa trên một trong những biện pháp này — ví dụ một trường hợp parser mà fuzz corpus chưa bao phủ, hoặc một khoảng trống syscall-filter — vui lòng nêu rõ điều đó trong báo cáo để bản vá có thể được triển khai cùng với một regression test.
