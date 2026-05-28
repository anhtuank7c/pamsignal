# Supported Linux Distributions

> 🌐 [English](../distros.md) · **Tiếng Việt**

PAMSignal được thiết kế cho Linux hiện đại có systemd native. Các bản phát hành cũ hơn có thể không có các hàm libc mà daemon gọi (`memfd_create`, dùng để cách ly thông tin xác thực trong đường dẫn alert dispatch), không có các chỉ thị systemd unit mà phần hardening của project dựa vào (`ProcSubset=pid`, `ProtectProc=invisible`, `ProtectClock=`, `ProtectHostname=`, `RestrictNamespaces=`, bộ syscall `@system-service`), hoặc không có phiên bản debhelper đủ mới để build package. Tài liệu này là tham chiếu chính thống cho câu hỏi "liệu pamsignal có chạy được trên host của tôi không?" và được tham chiếu từ [`SECURITY.md`](../../SECURITY.md) và chỉ mục tài liệu [README](README.md).

Các tier hỗ trợ dưới đây có ý nghĩa và cam kết khác nhau:

- **Tier 1 — Được CI kiểm thử**. Mỗi release được build và kiểm thử end-to-end trên các distro này. Các file `.deb` / `.rpm` được phát hành trên apt+dnf repo gh-pages là các artifact đã qua các bài kiểm thử này. Một regression ở Tier 1 sẽ làm thất bại release workflow và được xử lý như release blocker.
- **Tier 2 — Dự kiến hoạt động**. Codebase + dependencies nên hỗ trợ các distro này, nhưng không có bài kiểm thử tự động nào liên tục xác minh. Có thể có những lưu ý cụ thể (systemd cũ thiếu một số chỉ thị hardening, điểm `systemd-analyze security` live cao hơn đôi chút). Các báo cáo lỗi trên Tier 2 được chào đón và xử lý với độ ưu tiên bình thường.
- **Tier 3 — Không được hỗ trợ**. Pamsignal sẽ không compile, không cài đặt được, hoặc không áp dụng đủ hardening để các tuyên bố bảo mật trong [`docs/threat-model.md`](./threat-model.md) còn giá trị. Các báo cáo lỗi trên Tier 3 sẽ bị đóng với liên kết trỏ về tài liệu này.

Một thực tế quan trọng bạn cần ghi nhớ: **file `.deb` được phát hành được build một lần mỗi release trên CI runner Tier 1**, hiện tại có nghĩa là dependency runtime `libsystemd0` của package được ghim theo phiên bản libsystemd của runner (Ubuntu 24.04 kèm libsystemd0 255). Trên các Ubuntu và Debian cũ hơn, `apt install pamsignal` từ repo gh-pages sẽ từ chối với thông báo "unmet dependencies" ngay cả khi chính codebase có thể compile tốt. Các phương pháp cài đặt Tier 2 được ghi lại theo từng dòng.

## Tier 1 — Được CI kiểm thử

Release workflow gồm các job `test-deb` và `test-rpm` để build package, cài đặt dưới systemd trong container/VM sạch, cấu hình daemon với mock HTTPS webhook, thực hiện các sự kiện xác thực sshd thực, xác minh cấu trúc ECS payload, kiểm tra SIGHUP reload, rồi `apt purge` / `dnf remove` để xác nhận việc dọn dẹp. Pass = ship.

| Distro | Phiên bản | systemd | glibc | OpenSSH | sshd binary | Điểm bảo mật live | Phương pháp cài đặt |
|---|---|---|---|---|---|---|---|
| **Ubuntu** | 24.04 LTS (Noble) | 255 | 2.39 | 9.6 | `sshd` | 1.3 (OK) | `apt install pamsignal` từ repo gh-pages |
| **Fedora** | 44+ (`fedora:latest`) | 256+ | 2.40+ | 9.9+ | `sshd-session` | 1.3 (OK) | `dnf install pamsignal` từ repo gh-pages |
| **AlmaLinux** / **Rocky Linux** | 9 | 252 | 2.34 | 8.7 | `sshd` | 1.3 (OK) | `dnf install pamsignal` từ repo gh-pages |

Job `test-deb` thực hiện toàn bộ luồng E2E (`Type=notify` activation, brute-force sshd, SIGHUP reload, ECS payload). Các job `test-rpm` thực hiện cài đặt + gỡ cài đặt + xác minh bố cục file nhưng không thực hiện luồng daemon-dưới-systemd vì bài kiểm thử rpm chạy trong Docker container không có systemd PID 1.

## Tier 2 — Dự kiến hoạt động, không được kiểm thử chủ động

| Distro | Phiên bản | systemd | OpenSSH | Kết quả | Lưu ý |
|---|---|---|---|---|---|
| **Ubuntu** | 22.04 LTS (Jammy) | 249 | 8.9 | ✅ Compile + chạy | Không có `apt install pamsignal` từ repo gh-pages (dependency libsystemd ghim theo phiên bản 24.04). Build từ source qua `dpkg-buildpackage` trên host 22.04, hoặc chờ có per-distroseries pocket. |
| **Ubuntu** | 20.04 LTS (Focal) | 245 | 8.2p1 | ✅ Compile + chạy; **được CI kiểm thử liên tục**; Focal `.deb` per-release được đính kèm vào GitHub release | ESM-only từ 2025-04-30 — chỉ Ubuntu Pro subscriber mới nhận cập nhật bảo mật cấp host. Không có apt pocket gh-pages (cơ sở hạ tầng per-distroseries repo chỉ hiệu quả trên ~30+ host); tải `pamsignal_*_focal_amd64.deb` trực tiếp từ [trang GitHub release](https://github.com/anhtuank7c/pamsignal/releases) và cài bằng `apt install ./<file>.deb`. Hai chỉ thị systemd (`ProtectProc=invisible`, `ProcSubset=pid`, cả hai thêm vào systemd v247) được ghi log và bỏ qua khi load unit — systemd tương thích ngược, daemon vẫn chạy; điểm bảo mật live cao hơn ~1-2 điểm so với 22.04+ nhưng vẫn trong ngưỡng "OK". Lên kế hoạch migration sang 22.04 LTS (Standard Support đến tháng 4/2027) trước tháng 4/2030 khi Focal hết ESM. |
| **Ubuntu** | 26.04 (Resolute) | 259 | 9.10p2 | ✅ Compile + chạy (đã xác nhận bởi `tests/scenario.sh` ngày 2026-05-03; chưa có trong CI matrix) | Cùng lưu ý về package availability như 22.04 cho đến khi repo gh-pages có `resolute` pocket. |
| **Debian** | 12 (Bookworm) | 252 | 9.2p1 | ✅ Compile + chạy | Cùng lưu ý về package availability. Build từ source. |
| **Debian** | 13 (Trixie, dự kiến GA giữa 2026) | 257+ | 9.7+ | ✅ Compile + chạy | Cùng lưu ý về package availability. Có thể lên Tier 1 khi Trixie LTS ra mắt. |
| **RHEL** | 9 | 252 | 8.7 | ✅ Cùng binary với AlmaLinux 9 | rpm AlmaLinux 9 Tier 1 nên cài được trên RHEL 9 vì chúng tương thích ABI ở cấp libc + libsystemd. |
| **Fedora** | N-1 (43 tại thời điểm viết) | 254 | 9.6 | ✅ Compile + chạy | rpm Fedora Tier 1 nhắm vào `fedora:latest`; Fedora cũ hơn có thể hoặc không thỏa mãn các dependency string của nó. |

Với tất cả các dòng Tier 2, trình phân tích cú pháp, brute-force tracker và alert dispatch của pamsignal hoạt động giống hệt Tier 1 — sự khác biệt là ma sát về upgrade path (per-distroseries package pocket), không phải hành vi runtime. Điểm `systemd-analyze security` live trên Ubuntu 22.04 / Debian 12 có thể cao hơn 1–2 điểm so với baseline CI vì các phiên bản systemd mới hơn tính trọng số chỉ thị hơi khác nhau, nhưng mọi chỉ thị trong unit đều được tuân thủ.

**Ubuntu 20.04 (Focal) là trường hợp ngoại lệ trong Tier 2.** Nó được kiểm thử liên tục trong CI (các job `build-deb-focal` và `test-deb-focal` trong `.github/workflows/release-packages.yml` build và smoke-test một `.deb` nhắm vào Focal với container `ubuntu:20.04` mỗi release), và file `pamsignal_*_focal_amd64.deb` kết quả được đính kèm vào mỗi GitHub release. Operator cài bằng cách tải xuống trực tiếp thay vì dùng apt repo. Cách xử lý này dành riêng cho Focal vì phép tính vòng đời ESM — duy trì một build artifact release được kiểm thử chủ động thì rẻ, trong khi chạy một apt pocket đầy đủ cho một distro đã đóng băng, ESM-only thì không.

## Tier 3 — Không được hỗ trợ

| Distro | Phiên bản | systemd | glibc | Nguyên nhân không hỗ trợ |
|---|---|---|---|---|
| **Ubuntu** | 18.04 LTS (Bionic) | 237 | 2.27 | Nhiều chỉ thị sandbox bị thiếu (`ProtectProc=`, `ProcSubset=`, `ProtectClock=`, `ProtectHostname=`); điểm bảo mật live ~30+ |
| **Ubuntu** | 16.04 LTS (Xenial) | 229 | 2.23 | **Không compile được** — `memfd_create()` không có trong glibc 2.23; thông tin xác thực alert sẽ phải fallback sang argv exposure, mâu thuẫn trực tiếp với biện pháp giảm thiểu trong threat model (attack #3 trong `docs/threat-model.md`) |
| **Debian** | 11 (Bullseye) | 247 | 2.31 | Sandbox posture tương đương Ubuntu 20.04 (thiếu `ProtectProc`/`ProcSubset`) — nhưng Bullseye hiện không có trong CI matrix và không có Bullseye-targeted `.deb` nào được phát hành, nên chúng tôi không đưa ra claim hỗ trợ. Nếu bạn muốn chạy pamsignal trên Bullseye, build từ source qua `dpkg-buildpackage` trên host Bullseye — có thể hoạt động, nhưng bạn tự chịu trách nhiệm với regression. |
| **Debian** | ≤10 | ≤241 | ≤2.28 | Cùng vấn đề với các Ubuntu release cũ hơn |
| **CentOS / RHEL** | 7 (EOL 2024-06-30) | 219 | 2.17 | **Không compile được** — `memfd_create()` không có trong glibc 2.17 và kernel stock 3.10 thiếu syscall nền tảng (cần Linux 3.17+). Thông tin xác thực alert sẽ phải fallback sang argv exposure, mâu thuẫn với biện pháp giảm thiểu trong threat model (attack #3 trong `docs/threat-model.md`). systemd 219 cũng bỏ qua khoảng một nửa số chỉ thị hardening mà unit dựa vào. Xem [Tại sao CentOS / RHEL 7 không thể hỗ trợ được](#tại-sao-centos--rhel-7-không-thể-hỗ-trợ-được) bên dưới để biết migration path. |
| **CentOS / RHEL** | 8 (EOL 2021/2024) | 239 | 2.28 | Tương đương Ubuntu 18.04 — sandbox posture quá xa so với tuyên bố trong threat model |
| **Bất cứ thứ gì cũ hơn** | — | — | — | Tổ hợp glibc + systemd + OpenSSH mà hardening của pamsignal dựa vào không tồn tại. |

Các ngưỡng cắt này được nêu rõ ràng vì threat model đưa ra các tuyên bố cụ thể (compiler hardening, chỉ thị sandbox, `_EXE` allowlist matching so với đường dẫn binary thực trên đĩa) phụ thuộc vào các phiên bản này. Một cài đặt pamsignal trên Tier 3 có thể *chạy* trong nhiều trường hợp, nhưng sẽ chạy với isolation posture yếu hơn đáng kể so với những gì chính sách bảo mật quảng cáo — các operator triển khai nó sẽ đưa ra quyết định dựa trên những đảm bảo mà host thực sự không cung cấp.

## Tại sao CentOS / RHEL 7 không thể hỗ trợ được

Các operator với đội CentOS 7 đôi khi hỏi liệu ngưỡng cắt có thể được nới lỏng không. Câu trả lời là không, vì ba lý do độc lập:

1. **Không có syscall `memfd_create()` trong kernel.** Linux kernel đã thêm `memfd_create` trong 3.17 (tháng 10/2014). RHEL 7 / CentOS 7 stock kèm kernel 3.10 với vendor backport — `memfd_create` *không* nằm trong số các syscall được backport. Xác nhận trên host của bạn bằng `grep memfd_create /proc/kallsyms` (không có kết quả nghĩa là không có). pamsignal gọi nó tại [`../../src/notify.c:113`](../../src/notify.c) để build config file cho curl child trong một anonymous in-memory descriptor; tên descriptor `pamsignal-curl` chứa webhook URL, auth header và TLS-path config để `argv` của curl child không tiết lộ chúng trong `/proc/<pid>/cmdline` (có thể xác minh với `ps auxf` khi có active alert). Không có syscall đó, các chỗ duy nhất còn lại để đặt thông tin xác thực là argv (hiện thị cho mọi local user) hoặc tempfile (hiện thị cho bất kỳ ai có quyền đọc `/tmp` vào đúng lúc) — cả hai đều là mục tiêu trong [`../../docs/threat-model.md`](./threat-model.md) attack #3. Threat model sẽ phải bị hạ cấp để claim hỗ trợ CentOS 7, điều mà chúng tôi sẽ không làm.

2. **Không có glibc wrapper cho `memfd_create()`.** Ngay cả khi một kernel được backport có syscall này, glibc của RHEL 7 là 2.17 — wrapper được đưa vào glibc 2.27 (2018). Daemon gọi `memfd_create("pamsignal-curl", MFD_CLOEXEC)` như một hàm libc, không phải `syscall(SYS_memfd_create, ...)`. Chuyển sang dạng raw syscall là có thể, nhưng không giúp mở khóa CentOS 7 — xem điểm 1.

3. **EOL vào 2024-06-30.** CentOS 7 đã đến end-of-life vào ngày 30 tháng 6 năm 2024 — không còn cập nhật bảo mật upstream. Chạy daemon *giám sát bảo mật* trên một host không còn nhận cập nhật bảo mật là sự đảo ngược thứ tự ưu tiên: mức độ phơi nhiễm của host bây giờ lớn hơn những gì daemon phát hiện được, và bất kỳ CVE nào chưa được vá trong kernel, openssh, sudo hoặc systemd sẽ bị khai thác trước khi pamsignal có thể quan sát được một failed-auth event từ cuộc tấn công.

### Migration path cho các host CentOS 7

Ba lựa chọn thực tế, theo thứ tự gián đoạn tăng dần:

| Lựa chọn | Trông như thế nào | Khi nào nên dùng |
|---|---|---|
| **Migration in-place sang AlmaLinux 9 / Rocky Linux 9 / RHEL 9** | Chạy vendor migration script (`almalinux-deploy.sh` từ AlmaLinux, `migrate2rocky.sh` từ Rocky, `convert2rhel` từ Red Hat). Cả ba đều là Tier 1 / Tier 2 cho pamsignal, glibc 2.34, systemd 252, kernel 5.14 với cửa sổ hỗ trợ 10 năm. `/etc/sudoers`, sshd config và hầu hết app stack hiện có đều được chuyển tiếp không thay đổi. | Host là production server tồn tại lâu dài mà bạn muốn tiếp tục vận hành. Đây là con đường được khuyến nghị. |
| **Container deployment trên host CentOS 7 hiện có** | Chạy pamsignal trong container `podman run` (hoặc docker) dựa trên `almalinux:9` hoặc `ubuntu:24.04`. Container mang theo glibc mới hơn của riêng nó, nên ràng buộc ở cấp libc được giải quyết. **Điều kiện tiên quyết bắt buộc**: kernel host phải ≥ 3.17 — `uname -r` phải báo cáo một backport mới hơn stock 3.10 (một số host CentOS 7 chạy `kernel-lt` 5.4 hoặc `kernel-ml` 6.x của elrepo, hoạt động được; `3.10.0-1160.x.x.el7` gốc thì không). Container cũng cần quyền đọc `/var/log/journal` từ host (journal là thứ pamsignal quan sát), điều này khó về mặt vận hành khi journald của host là nguồn dữ liệu thực. | Host không thể migrate (hợp đồng hỗ trợ ứng dụng vendor, ràng buộc quy định, v.v.) và kernel của nó đã được cập nhật lên backport gần đây. |
| **Công cụ khác** | `auditd` đã có trên mọi host RHEL; kết hợp với `rsyslog`/`journald` forwarding đến SIEM (ví dụ: Wazuh, Splunk, Loki) và viết các correlation rule phát hiện brute-force phía SIEM. Đây là những gì hầu hết deployment CentOS 7 doanh nghiệp đã làm. | Host sẽ được ngừng hoạt động trong vòng 12 tháng tới và không đáng để migration, nhưng bạn vẫn muốn coverage phát hiện trong thời gian đó. |

Nếu lựa chọn là phương án 1, việc migration nhẹ nhàng về mặt vận hành: các script AlmaLinux/Rocky hoán đổi package in-place mà không cần reboot cho phần lớn quá trình chuyển đổi (một lần reboot cuối nạp kernel mới). `dnf install pamsignal` Tier 1 của pamsignal hoạt động ngay lập tức trên host sau migration.

## Kiến trúc

CI kiểm thử **x86_64** mà thôi. Codebase là architecture-neutral (không có inline asm, không có architecture-specific intrinsics), các compiler hardening flag bao gồm `-fcf-protection=full` chỉ khi được hỗ trợ, và chỉ thị systemd `SystemCallArchitectures=native` tự động thích ứng. **arm64 / aarch64** do đó là Tier 2 theo mặc định — dự kiến hoạt động, không được kiểm thử chủ động. Các báo cáo lỗi trên aarch64 được chào đón.

## Thêm distro vào Tier 1

Một dòng được chuyển từ Tier 2 lên Tier 1 khi:

1. CI matrix của release workflow gồm `test-deb` (hoặc `test-rpm`) có thêm entry strategy cho distro mục tiêu.
2. Bài kiểm thử end-to-end pass trên một CI run mới cho target đó.
3. Repo apt/dnf gh-pages được phát hành có thêm per-distroseries pocket để user có thể `apt install pamsignal` / `dnf install pamsignal` với package build trên base phù hợp.
4. Một regression trên target đó làm thất bại release workflow.

Tier 1 hiện tại được chọn theo những gì đã chạy trong CI. Mở rộng sang Ubuntu 22.04 + Ubuntu 26.04 + Debian 12 nằm trong roadmap; xem comment `# TODO: Tier 1 matrix expansion` gần job `test-deb` trong [`.github/workflows/release-packages.yml`](../../.github/workflows/release-packages.yml).

## Những gì tài liệu này không đề cập

- **Container runtime** (Docker, Podman, Kubernetes pod). PAMSignal là daemon đọc journald và phụ thuộc vào systemd thực sự. Chạy trong container không chia sẻ journal của host không được hỗ trợ theo thiết kế — threat model giả định daemon và các sự kiện nó đọc ở trên cùng kernel boundary.
- **Các distro musl-based** (Alpine Linux, Void). PAMSignal link với các hàm đặc thù glibc (wrapper `memfd_create()`, `clearenv()`, fallback syscall `close_range()`). musl libc của Alpine có thể hoặc không cung cấp signature tương thích; hiện chưa được kiểm thử.
- **Các BSD.** PAMSignal gọi trực tiếp `sd_journal_*`. Không có journald trên FreeBSD/OpenBSD/NetBSD; project sẽ cần một event source hoàn toàn khác. Ngoài phạm vi.

Để có security posture tốt, hãy chạy pamsignal trên distro Tier 1.
