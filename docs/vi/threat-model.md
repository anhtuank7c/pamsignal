# Threat Model

> 🌐 [English](../threat-model.md) · **Tiếng Việt**

Tài liệu này mô tả những gì PAMSignal bảo vệ, những gì nó chủ động không bảo vệ, và các lựa chọn thiết kế tạo nên tư thế đó. Đây là tài liệu tham chiếu để đánh giá các đóng góp trong tương lai: một thay đổi củng cố biện pháp giảm thiểu trong phạm vi là chào đón; một thay đổi kéo công việc vào daemon từ một lĩnh vực ngoài phạm vi thì không, dù về mặt kỹ thuật có thể thực hiện được.

Để báo cáo lỗ hổng bảo mật riêng tư, xem [`SECURITY.md`](../../SECURITY.md). Hai tài liệu bổ sung cho nhau — `SECURITY.md` hướng đến operator (cách báo cáo, phiên bản nào được hỗ trợ); tài liệu này hướng đến contributor (trách nhiệm của daemon là gì và không phải là gì).

## Mục đích

PAMSignal quan sát các sự kiện xác thực PAM trên một host duy nhất qua systemd journal và, khi các mẫu được cấu hình xảy ra (đăng nhập thất bại, ngưỡng brute-force), gửi cảnh báo qua HTTPS đến các kênh do operator lựa chọn. Nhiệm vụ của daemon là trở thành một **tín hiệu phát hiện đáng tin cậy** cho operator. Mọi biện pháp bảo vệ trong tài liệu này đều tồn tại để bảo tồn thuộc tính đó — rằng cảnh báo operator nhận được phản ánh chính xác những gì đã xảy ra trên host.

## Phạm vi quan sát

PAMSignal quan sát các sự kiện chạy qua PAM stack của host và vào journal của systemd. Đây là một nguồn tín hiệu *cụ thể*. Nó nắm bắt các kênh truy cập từ xa hàng ngày mà operator quan tâm — ssh, sftp, scp, rsync over ssh, sudo, su, login, xrdp + PAM, vsftpd / proftpd được cấu hình với PAM. Nó **không** quan sát mọi kênh qua đó một kết nối có thể đến host. Việc biết ranh giới một cách rõ ràng là một phần của threat model.

### Các kênh PAMSignal quan sát

| Kênh | Daemon nền | Những gì được ghi lại |
|---|---|---|
| Interactive SSH | `sshd` / `sshd-session` | LOGIN_SUCCESS, LOGIN_FAILED, SESSION_OPEN, SESSION_CLOSE |
| SFTP | `sshd` (subsystem) | Cùng các mục auth + session như SSH |
| SCP | `sshd` | Tương tự |
| Rsync over SSH | `sshd` | Tương tự |
| sudo / su | `pam_unix(sudo:auth)` / `pam_unix(su:auth)` | LOGIN_FAILED (với brute-force tracker keyed by `ruser`), SESSION_OPEN/CLOSE khi thành công |
| TTY / console login | `login` | SESSION_OPEN/CLOSE |
| xrdp với PAM | xrdp + `pam_unix` | SESSION_OPEN/CLOSE nếu được cấu hình dùng PAM |
| vsftpd / proftpd với PAM | self + `pam_unix` | Nếu FTP daemon được cấu hình xác thực qua PAM |
| systemd-logind sessions | `systemd-logind` | SESSION_OPEN/CLOSE khi mỗi session được tạo |

### Các kênh PAMSignal KHÔNG quan sát

Các kênh này xác thực qua các cơ chế mà journald không bao giờ thấy sự kiện PAM auth. Chúng là điểm mù thực sự trong bất kỳ lớp phát hiện dựa trên PAM nào, và chúng là các non-goal rõ ràng (mục ngoài phạm vi NS3 bao gồm journald bị xâm phạm; danh sách này mở rộng lý luận đó sang các nguồn tín hiệu *không phải* journald):

| Kênh | Cơ chế xác thực | Audit trail của operator nằm ở |
|---|---|---|
| WireGuard / OpenVPN / IPsec VPN | xác thực peer mã hóa | Log network-layer (kernel netlink events, `wg show` polling, log riêng của OpenVPN) |
| Tailscale SSH | Tailscale identity → mTLS | Tailscale admin console / `tailscale set --log` |
| AWS SSM Session Manager | IAM → SSM agent | CloudTrail |
| GCP Cloud IAP / OS Login | Google IAM | Cloud Audit Logs |
| Azure Bastion | Azure RBAC | Azure Activity Log |
| Teleport / Boundary / StrongDM | lớp identity riêng của chúng | Audit log của sản phẩm |
| `kubectl exec` vào container | Kubernetes RBAC | k8s API server audit log |
| IPMI / BMC / iDRAC / iLO | firmware BMC | Out-of-band management plane (riêng biệt, theo nhà cung cấp) |
| Serial console | truy cập vật lý | Không có ở tầng OS — bảo mật vật lý |
| NFS / SMB mounts | NFS/Kerberos / SMB | nfsd / smbd logs |
| `rclone` với HTTP/S3/GCS backend | API tokens | Log truy cập của cloud provider |
| Custom HTTP / REST / gRPC APIs | application-level | Audit log của ứng dụng |

### Hàm ý cho operator

Nếu PAMSignal là lớp alerting *duy nhất* trên một host, một kẻ tấn công tiếp cận host qua bất kỳ kênh bypass nào ở trên sẽ tạo ra **zero** sự kiện PAMSignal. Câu trả lời thực tế là **phát hiện theo lớp** — pamsignal cho các kênh PAM-stack (nơi traffic brute-force hàng ngày xuất hiện), cộng với một monitor riêng cho mỗi đường dẫn truy cập khác mà môi trường của operator lộ ra, tất cả đưa vào cùng SIEM qua pamsignal's ECS JSON webhook payload (hoặc tương đương). Các tài sản và kẻ tấn công trong threat model dưới đây được giới hạn trong các kênh PAM-stack; một operator triển khai pamsignal như một tín hiệu bảo mật nên xếp lớp tương ứng.

## Tài sản

Theo thứ tự ưu tiên:

1. **Tính toàn vẹn và kịp thời của cảnh báo.** Nếu kẻ tấn công có thể chặn, trì hoãn, giả mạo hoặc làm ngập cảnh báo, giá trị của PAMSignal với operator sẽ sụp đổ. Đây là tài sản quan trọng nhất.
2. **Thông tin xác thực cảnh báo.** Token bot Telegram, URL và bearer token Slack/Teams/Discord/custom-webhook, được lưu trong `/etc/pamsignal/pamsignal.conf` với quyền `0640 root:pamsignal`. Việc lộ chúng cho phép kẻ tấn công giả mạo cảnh báo (mạo danh PAMSignal với operator) và làm cạn kiệt giới hạn rate của kênh.
3. **Phong bì đặc quyền của system user `pamsignal`.** Chỉ đọc journal; không có capability, không tạo namespace, không load kernel-module, không SUID transition, không writable executable memory. Một sự xâm phạm thoát khỏi phong bì này là một sự xâm phạm toàn bộ host.
4. **Các mục journal có cấu trúc mà PAMSignal ghi** (`SYSLOG_IDENTIFIER=pamsignal`). Chúng cung cấp cho việc ingest SIEM downstream. Các mục phải phản ánh trạng thái quan sát thực tế, không phải nội dung do kẻ tấn công kiểm soát.

Journal của host, `/etc/passwd`, trạng thái kernel, v.v. **không phải** tài sản của PAMSignal để bảo vệ — chúng thuộc về journald, kernel và tư thế hardening rộng hơn của operator.

## Kẻ tấn công

Threat model giả định các năng lực kẻ tấn công sau. Một thay đổi nằm trong phạm vi nếu nó củng cố biện pháp bảo vệ của chúng ta chống lại các kẻ tấn công được đặt tên; ngoài phạm vi nếu nó dựa vào các giả định ngoài danh sách này.

### A. Kẻ tấn công từ xa bên ngoài (không có quyền truy cập host)

Năng lực: gửi traffic mạng tùy ý, quan sát phản hồi, chạy máy quét tự động chống lại các dịch vụ lộ ra của host. Không thể chạy code trên host. Lớp kẻ tấn công phổ biến nhất — máy quét brute-force SSH, credential-stuffing tự động.

Những gì chúng có thể làm mà PAMSignal quan tâm:
- Tạo ra các mục journal sshd trông có vẻ xác thực (sự kiện failed-password thực) ở tốc độ cao.
- Cố gắng làm tràn ngập brute-force tracker (table eviction, cooldown bypass, thao túng time-window bằng cách gửi sự kiện với timing được tạo thủ công).
- DoS đường cảnh báo gián tiếp bằng cách tạo đủ sự kiện đáng cảnh báo để làm cạn kiệt giới hạn rate của kênh chat của operator.

### B. Người dùng cục bộ không có đặc quyền (shell trên host, non-root, không trong group `pamsignal`)

Năng lực: bất kỳ syscall nào mà người dùng non-root có thể thực hiện trên một host Linux không có sandbox. Cụ thể: `logger(1)`, ghi vào `/dev/log`, đọc `/proc/<any>/cmdline`, đọc các mục journal mà group `systemd-journal` có thể đọc (thường chỉ của người dùng của họ), kết nối đến các local socket được phép.

Những gì chúng có thể làm mà PAMSignal quan tâm:
- Inject các dòng auth giả mạo qua `logger(1)` — `logger -t sshd "Failed password for root from ..."` — hy vọng PAMSignal sẽ xử lý chúng như sự kiện sshd thực.
- Kích hoạt các lần thất bại xác thực thực của chính họ (`sudo` với mật khẩu sai) để tạo cảnh báo.
- Đọc `/proc/<pamsignal-pid>/cmdline` tìm kiếm thông tin xác thực trong các tham số khởi động.
- Đọc `/proc/<pamsignal-pid>/environ` tìm kiếm thông tin xác thực bị rò rỉ qua môi trường.

### C. Người dùng cục bộ *trong* group `pamsignal` (lựa chọn có chủ đích của operator)

Năng lực: B + đọc `/etc/pamsignal/pamsignal.conf` (quyền `0640 root:pamsignal`). Đây là theo thiết kế — daemon cũng cần quyền đọc. Một operator thêm người dùng không phải system vào group `pamsignal` đang đưa ra quyết định tin tưởng có chủ đích và PAMSignal không giả vờ bảo vệ chống lại người dùng đó.

### D. Daemon `pamsignal` bị xâm phạm (ví dụ: parser RCE)

Năng lực: thực thi code tùy ý trong phong bì đặc quyền của daemon — người dùng `pamsignal`, không có cap, `SystemCallFilter` allowlist của systemd unit, `MemoryDenyWriteExecute=yes`, `ProtectSystem=strict`. Từ đây, xâm phạm toàn bộ host đòi hỏi một leo thang đặc quyền cục bộ khác (một kernel CVE riêng biệt, cấu hình sudo sai, một binary có thể ghi bởi pamsignal ở đâu đó trong PATH).

Những gì chúng có thể làm mà PAMSignal quan tâm:
- Đọc thông tin xác thực cảnh báo từ `/etc/pamsignal/pamsignal.conf`.
- Giả mạo các cảnh báo gửi đi đến các kênh được cấu hình.
- Chặn các cảnh báo thực bằng cách return sớm từ đường gửi cảnh báo.
- Cố thoát sandbox qua các syscall còn lại được cho phép bởi `SystemCallFilter`.

### E. Kẻ tấn công mạng trên đường cảnh báo

Năng lực: drop, delay, replay, hoặc cố MITM yêu cầu HTTPS từ daemon đến alert provider được cấu hình.

Những gì chúng có thể làm mà PAMSignal quan tâm:
- Drop cảnh báo (operator không bao giờ thấy sự kiện).
- MITM nếu TLS bị broken/downgraded/unverified.
- Không thể giải mã hoặc giả mạo yêu cầu được bảo vệ TLS đến một webhook được cấu hình đúng.

## Trong phạm vi: các cuộc tấn công mà daemon bảo vệ

Mỗi mục nêu tên cuộc tấn công, lớp kẻ tấn công từ trên, biện pháp giảm thiểu và vị trí source. Một regression trong bất kỳ mục nào là một lỗi bảo mật và thuộc [`SECURITY.md`](../../SECURITY.md).

### 1. Log injection qua `logger(1)` (B)

**Cuộc tấn công.** Một người dùng không có đặc quyền cục bộ chạy `logger -t sshd "Failed password for root from 1.2.3.4 port 22 ssh2"` để giả mạo một mục journal trông như lỗi xác thực sshd thực. Không có filtering, PAMSignal sẽ cảnh báo và brute-force tracker sẽ đếm nó.

**Biện pháp giảm thiểu.** `_EXE` allowlist trong `src/journal_watch.c:345-381`. Trường `_EXE` được ghi lại của mỗi mục journal (do journald tự đặt dựa trên binary thực sự được execve'd) phải resolve thành `sshd`, `sudo`, `su`, `login`, hoặc `systemd-logind` dưới một prefix hệ thống (`/usr/`, `/bin/`, `/sbin/`, `/lib/`, `/lib64/`, `/opt/`). Các mục không có `_EXE` (injection tổng hợp từ `/dev/log`) bị drop. `_EXE` của `logger` là `/usr/bin/logger` — không có trong allowlist, nên mục bị drop thầm lặng.

### 2. Bypass brute-force tracker (A, B)

**Cuộc tấn công.** Gửi các sự kiện failed-auth được tính thời gian cẩn thận để tăng bộ đếm per-key mà không bao giờ vượt ngưỡng; hoặc tạo đủ key kẻ tấn công riêng biệt để đẩy mục của target hợp lệ ra khỏi bảng.

**Biện pháp giảm thiểu.**
- `fail_window_sec` (`src/config.c:95`, mặc định 300s, phạm vi 1–86400) giới hạn time window để tổng hợp các lần thử. Logic sliding-window trong `src/journal_watch.c` reset count một khi `event->timestamp_usec - first_attempt_usec > window_usec`, nên kẻ tấn công không thể trải đều thất bại trên một window tùy ý dài để ở dưới ngưỡng.
- Eviction chọn **cũ nhất theo `last_attempt_usec`**, không phải theo `first_attempt_usec` — một kẻ tấn công liên tục làm mới `last_attempt_usec` bằng các thất bại mới không thể đẩy entry của chính họ ra; chúng đẩy một entry khác, ưu tiên thấp hơn ra.
- Per-key cooldown (`alert_cooldown_sec`, `src/journal_watch.c:223-232`) ngăn alert flooding từ một key đơn mà không mất bộ đếm bên dưới.

### 3. Lộ thông tin xác thực cảnh báo qua process metadata (B, D)

**Cuộc tấn công.** Đọc `/proc/<pamsignal-pid>/cmdline` hoặc `/proc/<pamsignal-curl-child-pid>/cmdline` để thu thập token bot Telegram, URL webhook, bearer token custom-webhook, hoặc đường dẫn trên đĩa của file cert / key mTLS client.

**Biện pháp giảm thiểu.** Mỗi sender theo kênh đều đi qua file curl `-K` config được tạo bởi `memfd_create()` (`src/notify.c:101`) mang URL, `webhook_auth_header` tùy chọn (từ v0.4.0), và các đường dẫn `cert =` / `key =` / `cacert =` tùy chọn (từ v0.4.0). Memfd được pin ở `fd 9` qua `dup2` (xóa `O_CLOEXEC` trên đích); mọi descriptor kế thừa khác được đóng trong tiến trình con trước `execv`. argv của tiến trình con curl byte-identical cho mọi lần gửi cảnh báo — `curl -s -S --max-time 10 --proto =https --proto-redir =https -H "Content-Type: application/json" -K /dev/fd/9 -d <body>` — bất kể kênh nào hay chế độ xác thực nào đang được dùng. Một người dùng không có đặc quyền đọc `/proc/*/cmdline` không thể biết liệu có token, client cert, hay cả hai được cấu hình, chứ chưa nói đến việc thu thập các giá trị đó. argv của daemon cha là `pamsignal --foreground` cộng với `--config <path>` tùy chọn — không có thông tin xác thực nào ở đó.

### 4. Hijack alert dispatch qua `PATH` / `LD_PRELOAD` (D)

**Cuộc tấn công.** Một daemon pamsignal bị xâm phạm thao túng môi trường của tiến trình con curl để chuyển hướng nó qua một binary hoặc library do kẻ tấn công kiểm soát.

**Biện pháp giảm thiểu.** Tiến trình con curl thực hiện `clearenv()` (`src/notify.c:184`), rồi `setenv("PATH", "/usr/bin:/bin", 1)`, rồi `execv("/usr/bin/curl", …)` với đường dẫn tuyệt đối nên `PATH` không được tham khảo. `LD_PRELOAD` bị drop bởi `clearenv()`. systemd unit cũng đặt `Environment=PATH=/usr/bin:/bin` (`pamsignal.service.in:30`) để phòng thủ theo chiều sâu khi daemon được khởi động ngoài unit.

### 5. TLS downgrade / cleartext webhook (E)

**Cuộc tấn công.** Một `webhook_url = http://...` được cấu hình sai hoặc chuyển hướng sang `http://` sẽ lộ nội dung cảnh báo và thông tin xác thực cho người quan sát mạng thụ động.

**Biện pháp giảm thiểu.** URL validator của PAMSignal từ chối các URL không phải `https://` tại thời điểm load config (`src/config.c`); lời gọi curl truyền `--proto =https --proto-redir =https` (`src/notify.c`) nên ngay cả kẻ tấn công quản lý inject một redirect `Location: http://...` cũng không thể bắt curl theo nó.

### 6. Alert payload injection (A → D)

**Cuộc tấn công.** Một username, hostname, hoặc trường PAM-message chứa các ký tự có ý nghĩa JSON hoặc control byte, dẫn đến payload bị dị dạng hoặc thoát ra khỏi JSON quoting.

**Biện pháp giảm thiểu.**
- `sanitize_string()` (`src/utils.c:13`) thay thế tất cả control character (0x00–0x1F + 0x7F) bằng `?` trên mọi username và target_username đã trích xuất, ngay sau khi parsing.
- `is_valid_ip()` (`src/utils.c:21`) yêu cầu `inet_pton` chấp nhận source IP; thất bại xóa trường.
- `json_escape()` (`src/notify.c:27`) RFC 8259 escape `"`, `\`, tất cả byte 0x00–0x1F, cộng với các short escape chuẩn cho `\b\f\n\r\t`. Ngay cả khi `sanitize_string` bị regression, JSON quoting vẫn giữ.
- Tất cả extraction được bounded: username vào buffer 64-byte với marker truncation `+` (`src/utils.c:63-77`), hostname bounded bởi `event.hostname[256]`, `sscanf` dùng width specifier ở mọi nơi.

### 7. Thoát sandbox từ daemon bị xâm phạm (D)

**Cuộc tấn công.** Parser-level RCE trong code C đạt được thực thi tùy ý ở mức người dùng `pamsignal`, rồi cố leo thang lên root.

**Biện pháp giảm thiểu (chiều sâu, không hoàn hảo):**
- `User=pamsignal Group=pamsignal` (không có đặc quyền để bắt đầu).
- `CapabilityBoundingSet=` trống (`pamsignal.service.in:53`).
- `NoNewPrivileges=yes` (`pamsignal.service.in:38`) — các binary SUID `setuid` trở thành no-op.
- `MemoryDenyWriteExecute=yes` (`pamsignal.service.in:46`) — shellcode injection đòi hỏi một kernel bug riêng biệt.
- `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectKernelLogs=yes`, `ProtectControlGroups=yes`.
- `RestrictNamespaces=yes`, `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, `LockPersonality=yes`.
- `SystemCallFilter=@system-service ~@privileged @resources` — bpf, mount, kexec, finit_module, v.v. đều bị từ chối.
- `RLIMIT_NPROC` giới hạn ở 64 trong `src/main.c` nên fork-bomb trong đường cảnh báo không thể làm cạn kiệt process slot.
- `prctl(PR_SET_NO_NEW_PRIVS, 1)` được đặt sớm trong `src/main.c` ngay cả bên ngoài unit.

Điểm systemd-analyze security (CI-gated ở ≤30 trên thang 0–100 nội bộ; hiện tại 22) là guard regression cho các directive này.

### 8. Lỗi memory-safety trong C parser (A → D)

**Cuộc tấn công.** Nội dung mục journal được tạo thủ công kích hoạt buffer overflow / use-after-free / integer overflow trong `ps_parse_message` hoặc xử lý string downstream.

**Biện pháp giảm thiểu.**
- Compiler hardening: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=3`, `-fcf-protection=full` (Intel CET), `-fstack-clash-protection`, full RELRO, PIE, `-z noexecstack`, `-z separate-code` (`meson.build`).
- Harness libFuzzer trong `tests/fuzz_parse_message.c` bao phủ điểm vào chính của parser. Chạy với `CC=clang meson setup -Dfuzz=enabled build-fuzz && build-fuzz/fuzz_parse_message tests/fuzz/parse_message_corpus -max_total_time=60`.
- 98 test CMocka trên bốn suite, bao gồm parser edge case (username bị truncate, control character, IP-validation failure, thông báo PAM multi-`user=`, IPv6 literal).
- clang-tidy + clang-analyzer trong CI với `WarningsAsErrors` trên family checker `clang-analyzer-security.*`.

### 9. Alert-volume DoS từ một source IP đơn (A)

**Cuộc tấn công.** Một máy quét chạy mãi mãi chống lại một IP, tạo ra hàng nghìn cảnh báo brute-force làm ngập kênh chat của operator.

**Biện pháp giảm thiểu.** Per-source-IP cooldown trong `src/journal_watch.c:223-232`. Sau khi một cảnh báo threshold-breach được kích hoạt, cùng IP đó không thể kích hoạt cảnh báo khác trong `alert_cooldown_sec` giây (mặc định 60s), nhưng bộ đếm bên dưới và các mục journal vẫn tiếp tục. Điều này nén các cảnh báo tấn công liên tục thành một ping chat mỗi cooldown period mà không mất khả năng quan sát.

## Ngoài phạm vi: các cuộc tấn công PAMSignal không bảo vệ

Đây là các non-goal có chủ đích. Một thay đổi cố gắng mở rộng daemon để bảo vệ chống lại bất kỳ mục nào trong số chúng sẽ bị từ chối trừ khi toàn bộ threat model đang được mở rộng.

### NS1. Kẻ tấn công đã có root trên host được giám sát

Một khi kẻ tấn công có root, họ có thể `systemctl stop pamsignal`, thay thế `/usr/bin/pamsignal` bằng một no-op, chỉnh sửa `/etc/pamsignal/pamsignal.conf` để trỏ cảnh báo đến webhook của họ, hoặc `kill -STOP` daemon để đóng băng nó. Không có usermode daemon nào bảo vệ chống lại root, và pamsignal không giả vờ như vậy.

### NS2. Kẻ tấn công trong group `pamsignal`

Group này là ranh giới truy cập đọc có chủ đích cho file cấu hình. Một operator thêm người dùng không phải system vào đó đang tự nguyện mở rộng tin tưởng cho người dùng đó. PAMSignal không bảo vệ chống lại các thành viên của group mang thông tin xác thực của chính nó.

### NS3. journald bị xâm phạm

PAMSignal tin tưởng các trường `_EXE`, `_PID`, `_UID`, và `_HOSTNAME` của journald. journald đặt các trường này từ metadata process do kernel cung cấp tại thời điểm ghi; PAMSignal không thể xác minh độc lập chúng. Nếu journald bị xâm phạm (hoặc, thực tế hơn, nếu kernel's `/proc/<pid>/exe` lookup bị hỏng bởi một kernel CVE), `_EXE` allowlist không có tác dụng.

### NS4. `libsystemd` hoặc `curl` bị xâm phạm

PAMSignal link với `libsystemd` và exec `/usr/bin/curl`. Một trojan trong một trong hai là vấn đề host-compromise mà package manager và chuỗi cung ứng package có chữ ký nên bắt ở upstream của PAMSignal.

### NS5. Alert provider bị xâm phạm

Bằng cách cấu hình `telegram_bot_token` / `slack_webhook_url` / v.v., operator mở rộng tin tưởng đến các dịch vụ đó. Nếu Telegram bị xâm phạm, cảnh báo của operator sẽ bị kẻ tấn công nhìn thấy. Biện pháp giảm thiểu là lựa chọn của operator — dùng kênh custom-webhook trỏ đến cơ sở hạ tầng do operator kiểm soát.

### NS6. Độ bền gửi cảnh báo khi mạng gặp sự cố

Cảnh báo PAMSignal là fire-and-forget: một tiến trình con curl được fork+exec'd, tiến trình cha không chờ hoàn thành hay retry khi thất bại. Nếu mạng bị sập hoặc alert provider không đến được, cảnh báo sẽ **bị mất**. Đây là một đánh đổi có chủ đích — giao hàng bền vững đòi hỏi queueing, queueing đòi hỏi on-disk state, mở rộng bề mặt tấn công (tấn công state-corruption, DoS disk-full, v.v.). Operator cần giao hàng cảnh báo bền vững nên gửi đến custom webhook receiver họ kiểm soát, với logic queueing và retry riêng của họ.

### NS7. Tương quan đa host

Mỗi instance PAMSignal độc lập. Không có aggregation trung tâm, không có bảng brute-force chia sẻ giữa các host. Một kẻ tấn công tấn công 50 host với 4 lần thử mỗi host sẽ không kích hoạt bất kỳ ngưỡng nào, ngay cả khi mẫu tích lũy rõ ràng là một cuộc tấn công. Operator cần tương quan đa host sẽ pipe đầu ra JSON-webhook vào một SIEM thực hiện tương quan đúng cách.

### NS8. Alert payload được ký HMAC

Kể từ v0.4.0, kênh custom-webhook có thể xác thực đến receiver của nó qua shared-secret HTTP header (`webhook_auth_header`, ví dụ: `Authorization: Bearer …`, API key, hoặc Splunk/Datadog token) hoặc mTLS (`webhook_client_cert` + `webhook_client_key`, `webhook_ca_bundle` tùy chọn), theo cách cộng thêm. Cả hai đều là xác thực *transport-layer*: receiver biết kết nối đến từ người nắm giữ secret / cert. **Những gì pamsignal vẫn không làm là HMAC-sign *payload* — không có body signature, không có replay-protection nonce, không có per-event MAC.** Một receiver đã chấp nhận một request không thể chứng minh body không bị replay bởi một client đã xác thực trước đó, và một token bị rò rỉ có thể replay cho đến khi được rotate. HMAC payload signing có chủ đích ngoài phạm vi: nó sẽ đòi hỏi link libcrypto vào daemon (hoặc tự làm SHA-256), và threat model mà nó bảo vệ chống lại (giao hàng bên thứ ba qua intermediary không tin cậy, theo kiểu GitHub/Stripe webhook delivery) không khớp với deployment shape của pamsignal (operator → lớp ingest SIEM của chính operator qua TLS). Operator với adversary model đó nên pre-share state qua mTLS và để receiver thực hiện payload-level deduplication trên `(host, @timestamp, event.action)`. Các kênh chat (Telegram, Slack, Teams, WhatsApp, Discord) xác thực bằng scheme token-in-URL hoặc bearer riêng của mỗi provider; pamsignal không thêm lớp auth thứ hai lên trên.

### NS9. Bảo vệ chống admin misconfiguration

Nếu operator đặt `pamsignal.conf` ở quyền `0644` (world-readable) và lưu thông tin xác thực trong đó, PAMSignal sẽ khởi động (sau khi cảnh báo tại thời điểm load config) nhưng thông tin xác thực bị lộ. Cải thiện mặc định là chào đón như feature request; coi đây là lỗi bảo mật thì không phù hợp.

### NS10. Network-side DoS nhắm vào tài nguyên của chính daemon

Kẻ tấn công có thể tạo ra hàng triệu sự kiện journal hợp lệ mỗi giây có thể bão hòa CPU của PAMSignal. Daemon không tự giới hạn rate đầu vào của mình — nó xử lý bất cứ thứ gì journald đưa cho nó. Theo điểm systemd-analyze, daemon không thể fork-bomb hệ thống (`RLIMIT_NPROC=64`) hoặc làm cạn kiệt bộ nhớ vượt quá cấu trúc dữ liệu bounded của nó (`max_tracked_ips`), nhưng nó có thể bị chậm lại. Câu trả lời chuẩn cho input-side DoS trên một host đơn là firewalling, auto-banning kiểu fail2ban, hoặc journald-side rate limits (`RateLimitIntervalSec=`, `RateLimitBurst=`).

## Ranh giới tin tưởng

Ranh giới tin tưởng là nơi trong hệ thống mà dữ liệu không tin cậy hoặc bị ảnh hưởng bởi kẻ tấn công vượt qua vào vùng được xử lý như đã được định dạng đúng. Mỗi ranh giới có một validator được chỉ định; lỗi trong validator là lớp lỗi ưu tiên cao nhất.

| Ranh giới | Phía không tin cậy | Validator | Source |
|---|---|---|---|
| Journal entry → parser | Trường `MESSAGE` được journald ghi lại | `ps_parse_message` + `_EXE` allowlist | `src/utils.c`, `src/journal_watch.c:345-381` |
| Conf file → daemon config | Nội dung file (do root kiểm soát nhưng trên đĩa) | `ps_config_load` + kiểm tra permission/ownership | `src/config.c:249-300` |
| Event → JSON webhook payload | `event->username`, `event->source_ip`, `event->hostname` | `sanitize_string` + `json_escape` | `src/utils.c:13`, `src/notify.c:27` |
| Daemon → curl child | URL webhook, bearer token, đường dẫn cert/key/CA mTLS, body | memfd-backed `--config` (URL + `header =` tùy chọn + `cert/key/cacert =` tùy chọn), fixed argv, `--proto =https`, absolute-path `execv` | `src/notify.c:101-209` |
| Config → curl `-K` parser | Giá trị chuỗi từ `pamsignal.conf` | `is_https_url` (URL), `is_http_header` (auth header), `validate_tls_path` (cert/key/CA paths từ chối `"`, `\`, control char, follow-symlinks, world-readable key) | `src/config.c:140-330` |

## Hạn chế thiết kế (đánh đổi có chủ đích)

Đây là những lựa chọn dự án đã thực hiện *cho* sự đơn giản và bề mặt tấn công nhỏ hơn, với nhận thức đầy đủ về chi phí:

- **Brute-force tracker trong bộ nhớ**, bị xóa khi restart (được bảo tồn qua SIGHUP). Chi phí: restart daemon reset bộ đếm per-IP, tạm thời mở cửa cho kẻ tấn công retry. Được giảm thiểu bởi `fail_window_sec` ngắn (mặc định 300s — khớp với thời gian restart điển hình).
- **Không load PAM module.** PAMSignal không chạy bên trong PAM stack; nó quan sát các đầu ra của stack. Chi phí: nó không thể can thiệp để *chặn* một lần thử xác thực, chỉ cảnh báo về nó. Lợi ích: không có privileged code nào trong PAM authentication path.
- **Không có persistent state trên đĩa.** Daemon không ghi gì vào `/var/lib/`. Chi phí: không có lịch sử brute-force qua các lần restart, không có state offline-analysis. Lợi ích: không có gì để corrupt, không có gì để disk-fill, không có gì để rò rỉ.
- **Phạm vi một host.** Không có clustering, không có shared state, không có central server. Chi phí: aggregation là mối quan tâm SIEM ngoài băng. Lợi ích: daemon đơn tiến trình, không có network listening port, không có xác thực giữa các instance.
- **Fire-and-forget alerts.** Đã thảo luận trong NS6 ở trên.

Đây là những ranh giới mà người đề xuất tính năng nên dừng lại và hỏi liệu tính năng có đáng với chi phí — và câu trả lời thường là "không, hãy dùng custom-webhook escape hatch."

## Hướng dẫn cho operator

Một cài đặt PAMSignal chỉ an toàn như cấu hình xung quanh nó. Threat model giả định operator tuân theo các hướng dẫn này:

1. **Không thêm người dùng không tin tưởng vào group `pamsignal`.** Làm vậy mở rộng quyền đọc file cấu hình (và do đó quyền truy cập thông tin xác thực cảnh báo) cho những người dùng đó. `postinst` của package không thêm ai; thành viên duy nhất theo mặc định là daemon.
2. **Giữ `/etc/pamsignal/pamsignal.conf` ở `0640 root:pamsignal`.** Package đặt điều này khi cài đặt lần đầu. PAMSignal cảnh báo khi khởi động nếu quyền lỏng hơn; nó không từ chối khởi động, phòng trường hợp operator cố tình chạy với quyền nghiêm ngặt hơn.
3. **Với triển khai high-assurance, hãy gửi cảnh báo đến custom webhook bạn kiểm soát.** Các nhà cung cấp chat bên thứ ba (Telegram, Slack, Teams, Discord, WhatsApp) thấy metadata cảnh báo của bạn. Một webhook trên cơ sở hạ tầng bạn kiểm soát cho bạn storage bền vững, aggregation đa host, và kiểm soát đầy đủ về retention. Xác thực kết nối đến receiver bằng `webhook_auth_header` (Bearer / API key / Splunk HEC / Datadog), hoặc — nếu môi trường của bạn chạy PKI — `webhook_client_cert` + `webhook_client_key` cho mTLS. Hai cách kết hợp theo kiểu cộng thêm. Xem [Configuration → Custom webhook authentication](configuration.md#xác-thực-custom-webhook).
4. **Đặt `webhook_client_key` ở quyền `0640 root:pamsignal`** (hoặc `0600 pamsignal:pamsignal` nếu bạn chạy daemon bằng người dùng đó). PAMSignal từ chối khởi động nếu key có thể đọc bởi group hoặc world. Cert và CA bundle không có ràng buộc tương tự — chúng là tài liệu công khai.
5. **Rotate thông tin xác thực cảnh báo định kỳ.** PAMSignal không tự rotate thông tin xác thực; rotation là trách nhiệm của operator. Với token shared-secret (token bot Telegram, `webhook_auth_header`, v.v.), cập nhật `pamsignal.conf` và `systemctl reload pamsignal`. Với `webhook_client_cert` / `webhook_client_key`, thay thế file tại chỗ — cert manager (cert-manager / certbot / `systemd-creds`) xử lý atomic rotation; lần gửi cảnh báo tiếp theo tự động lấy file mới. SIGHUP không cần thiết để rotate cert/key vì các đường dẫn trong config không thay đổi.
6. **Không chạy PAMSignal bằng `root`.** Nó từ chối dù sao, nhưng kỳ vọng cơ bản là daemon ở lại người dùng `pamsignal` do package tạo. Override unit tùy chỉnh thay đổi `User=` làm mất hiệu lực threat model.
7. **Để phòng thủ theo chiều sâu trên đường cảnh báo, kết hợp PAMSignal với một instance fail2ban (hoặc tương đương)** tiêu thụ cùng các mục journal để thêm firewall rule. PAMSignal quan sát; fail2ban hành động. Hai cái bổ sung nhau, không dư thừa; xem `../../examples/fail2ban/` trong repo này để xem integration mẫu.

## Báo cáo vấn đề

Các lỗ hổng nên được báo cáo riêng tư theo kênh và timeline trong [`SECURITY.md`](../../SECURITY.md). Phân chia in-scope/out-of-scope trong `SECURITY.md` khớp với tài liệu này; tài liệu này cung cấp lý luận kỹ thuật đằng sau phân chia đó.
