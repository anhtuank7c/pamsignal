# Deployment

> [English](../deployment.md) · **Tiếng Việt**

## Cài đặt

Con đường được khuyến nghị là dùng file `.deb` hoặc `.rpm` đã phát hành từ project repo (cùng các lệnh một dòng trong [README quick start](README.md#1-cài-đặt)). Các package này tạo system user `pamsignal`, thêm user này vào group `systemd-journal`, và đặt quyền file config thành `root:pamsignal 0640`. Riêng `.deb` còn enable và start unit; trên Fedora / RHEL, unit tuân theo preset policy của distro, nên hãy chạy các lệnh ở mục [Khởi động service](#khởi-động-service). Khi cài qua `apt` hoặc `dnf` bạn có thể bỏ qua thẳng đến [Cấu hình](#cấu-hình).

Nếu build từ source, bạn tự thực hiện các bước đó; xem phần "Source build" bên dưới.

### Debian / Ubuntu (apt)

```bash
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://anhtuank7c.github.io/pamsignal/key.asc \
  | sudo gpg --dearmor -o /etc/apt/keyrings/pamsignal.gpg
echo "deb [signed-by=/etc/apt/keyrings/pamsignal.gpg] https://anhtuank7c.github.io/pamsignal stable main" \
  | sudo tee /etc/apt/sources.list.d/pamsignal.list
# Chỉ refresh repo PamSignal, để một repo bên thứ ba bị lỗi không chặn được quá trình cài đặt
sudo apt update -o Dir::Etc::sourcelist="sources.list.d/pamsignal.list" \
  -o Dir::Etc::sourceparts="-" -o APT::Get::List-Cleanup="0"
sudo apt install pamsignal
```

Lệnh `apt update` được giới hạn ở đây chỉ refresh `pamsignal.list`. Nếu một repo bên thứ ba khác trên máy bị lỗi (ví dụ `NO_PUBKEY` hết hạn), lệnh `apt update && apt install` thông thường sẽ thoát với mã lỗi khác 0 và không bao giờ chạy tới bước cài đặt; các cờ `-o Dir::Etc::*` né vấn đề này bằng cách chỉ đọc đúng source của PamSignal. Bỏ các cờ này nếu bạn muốn chạy `apt update` đầy đủ.

`/etc/apt/keyrings` là vị trí tiêu chuẩn cho các APT signing key được cài bởi system administrator (theo `sources.list(5)`); dòng `install -d` là idempotent và an toàn để chạy lại trên các hệ thống đã có thư mục này.

Package cài đặt `/usr/bin/pamsignal`, `/usr/lib/systemd/system/pamsignal.service`, `/etc/pamsignal/pamsignal.conf`, `/usr/share/man/man8/pamsignal.8.gz` và `/usr/share/man/man5/pamsignal.conf.5.gz`. User `pamsignal` và membership trong group `systemd-journal` được tạo trong `postinst`. Tiếp tục tại [Cấu hình](#cấu-hình).

### Ubuntu 20.04 (Focal)

Focal không có apt repository. Mỗi bản release đính kèm một bản build Focal đã ký (`pamsignal_<version>-1_focal_amd64.deb` cùng chữ ký detached `.asc`) trên [GitHub release](https://github.com/anhtuank7c/pamsignal/releases):

```bash
VERSION=0.8.1
curl -fLO "https://github.com/anhtuank7c/pamsignal/releases/download/v${VERSION}/pamsignal_${VERSION}-1_focal_amd64.deb"
sudo apt install "./pamsignal_${VERSION}-1_focal_amd64.deb"
```

Xem [Các distro được hỗ trợ](./distros.md) để biết các lưu ý riêng cho Focal.

### Fedora / RHEL / AlmaLinux / Rocky (dnf)

```bash
# Fedora
sudo dnf config-manager addrepo \
  --from-repofile=https://anhtuank7c.github.io/pamsignal/rpm/fedora/pamsignal.repo

# RHEL 9 / AlmaLinux 9 / Rocky Linux 9
sudo dnf config-manager --add-repo \
  https://anhtuank7c.github.io/pamsignal/rpm/el9/pamsignal.repo

sudo dnf install pamsignal
```

Bố cục giống với deb (`/usr/bin`, `/usr/lib/systemd/system`, `/etc/pamsignal`, các man page `pamsignal(8)` và `pamsignal.conf(5)`); bản thân `/etc/pamsignal` có quyền `root:pamsignal 0750`. User và group `pamsignal` được tạo trong block `%pre` của spec. Tiếp tục tại [Cấu hình](#cấu-hình).

### Source build (`meson install`)

```bash
# Build
meson setup build
meson compile -C build

# Cài đặt binary, service file, example config và các man page
sudo meson install -C build
```

Với `--prefix=/usr/local` mặc định bạn sẽ có:

- `/usr/local/bin/pamsignal`: binary (quy ước hiện đại của systemd: các daemon định hướng admin chia sẻ `/usr/bin` với mọi thứ khác, giống như `journalctl`, `systemctl`, `podman`, `containerd`)
- `/usr/local/lib/systemd/system/pamsignal.service`: systemd unit (đường dẫn tìm kiếm vendor unit)
- `/usr/local/etc/pamsignal/pamsignal.conf`: example config (từ `pamsignal.conf.example`)
- `/usr/local/share/man/man8/pamsignal.8` và `/usr/local/share/man/man5/pamsignal.conf.5`: các man page

Để cài toàn hệ thống theo bố cục giống package (`/usr/bin`, `/usr/lib/systemd/system`, `/etc/pamsignal`), cấu hình lại với `meson setup build --prefix=/usr --sysconfdir=/etc`.

Source build **không** tạo system user `pamsignal` hay khóa quyền file config. Hãy tự thực hiện các bước đó trước khi khởi động service:

```bash
sudo useradd -r -s /usr/sbin/nologin pamsignal
sudo usermod -aG systemd-journal pamsignal

# Khóa example config để thông tin xác thực chỉ đọc được bởi
# daemon (group=pamsignal) nhưng không public. Các script postinst
# của deb/rpm thực hiện điều này tự động khi cài package.
sudo chown root:pamsignal /usr/local/etc/pamsignal/pamsignal.conf
sudo chmod 0640 /usr/local/etc/pamsignal/pamsignal.conf
```

## Cấu hình

Chỉnh sửa file config. Đường dẫn tùy thuộc vào cách bạn đã cài đặt:

- Cài package (deb/rpm) hoặc source build với `--prefix=/usr --sysconfdir=/etc`: `/etc/pamsignal/pamsignal.conf`
- Source build với `--prefix=/usr/local` mặc định: `/usr/local/etc/pamsignal/pamsignal.conf`

```bash
sudo editor /etc/pamsignal/pamsignal.conf
```

Tất cả các giá trị đều tùy chọn; mặc định đã hợp lý. Để bật cảnh báo, thêm thông tin xác thực kênh của bạn (ví dụ: Telegram, Slack):

```ini
telegram_bot_token = <bot_token>
telegram_chat_id = <chat_id>
```

Xem [Configuration](./configuration.md) để biết tất cả các tùy chọn.

Kiểm tra file và gửi thử một tin nhắn trước khi áp dụng. Cả hai lệnh đều từ chối chạy với quyền root; hãy chạy bằng service user để việc kiểm tra quyền sở hữu file khớp với những gì daemon thấy:

```bash
sudo -u pamsignal pamsignal --check-config   # validate, list enabled channels, exit 0 if OK
sudo -u pamsignal pamsignal --test-alert     # send a test message to every configured channel
```

### Xác thực custom webhook

Nếu bạn trỏ `webhook_url` đến SIEM hoặc receiver của riêng mình, hãy cấu hình xác thực với `webhook_auth_header` (Bearer token, API key, v.v.) hoặc, với môi trường đã có PKI, `webhook_client_cert` + `webhook_client_key` cho mTLS:

```bash
# Đặt client cert + key trong thư mục config của daemon.
sudo install -d -o root -g pamsignal -m 0750 /etc/pamsignal
sudo install -o root -g pamsignal -m 0644 webhook-client.crt /etc/pamsignal/
sudo install -o pamsignal -g pamsignal -m 0600 webhook-client.key /etc/pamsignal/
```

Daemon từ chối config nếu `webhook_client_key` có quyền đọc cho group hoặc other, nên một key `0640` (bố cục mà chính `pamsignal.conf` dùng) sẽ bị từ chối. Key phải thuộc sở hữu của root hoặc daemon user; vì chỉ owner được đọc, hãy dùng `pamsignal:pamsignal 0600`. Certificate và CA bundle không phải bí mật nên có thể để `0644`. Nếu cert manager của bạn (cert-manager, certbot, `systemd-creds`) triển khai key ở nơi khác, hãy trỏ `webhook_client_key` đến đường dẫn đó; pamsignal mở file với `O_NOFOLLOW` và xác thực quyền sở hữu cùng mode khi mỗi lần load config. Xem [Configuration → Xác thực custom webhook](./configuration.md#xác-thực-custom-webhook) để biết tham chiếu đầy đủ.

## Khởi động service

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pamsignal
```

## Kiểm tra

```bash
# Kiểm tra trạng thái
sudo systemctl status pamsignal

# Xem log
journalctl -u pamsignal -f

# Chỉ xem các sự kiện pamsignal
journalctl -t pamsignal -f
```

## Reload config

Sau khi chỉnh sửa `/etc/pamsignal/pamsignal.conf`:

```bash
sudo systemctl reload pamsignal
```

Lệnh này gửi SIGHUP: không có downtime, không cần restart. Daemon nạp file vào một bản tạm và chỉ thay thế khi file hợp lệ; nếu không, nó ghi log `pamsignal: config reload failed, keeping current config` và tiếp tục chạy với cấu hình cũ. Một lần reload thành công vẫn giữ các bộ đếm login thất bại và cooldown của brute-force tracker (bảng chỉ bị cắt bớt khi `max_tracked_ips` nhỏ đi). Hãy chạy `--check-config` trước để xem lý do file bị từ chối.

## Dừng

```bash
sudo systemctl stop pamsignal
```

## Nâng cấp

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install --only-upgrade pamsignal

# Fedora / RHEL / AlmaLinux / Rocky
sudo dnf upgrade pamsignal
```

Cả hai loại package đều restart service đang chạy sau khi nâng cấp. File `/etc/pamsignal/pamsignal.conf` bạn đã sửa được giữ lại: nếu bản mặc định trong package cũng thay đổi, `dpkg` sẽ hỏi trước khi thay conffile bạn đã sửa, còn `rpm` (`%config(noreplace)`) giữ file của bạn và ghi bản mặc định mới bên cạnh dưới tên `pamsignal.conf.rpmnew`. Trên Focal, tải `.deb` của bản release mới và chạy lại `sudo apt install ./<file>.deb`. Với source build, build lại, chạy `sudo meson install -C build`, rồi `sudo systemctl daemon-reload && sudo systemctl restart pamsignal`.

## Gỡ cài đặt

Lệnh phù hợp phụ thuộc vào cách bạn đã cài đặt pamsignal. Nếu bạn dùng `.deb` hoặc `.rpm` đã phát hành (con đường trong README của project), package manager sẽ xử lý mọi thứ cho bạn. Hướng dẫn thủ công chỉ dành cho các cài đặt thực hiện từ source qua `meson install`.

### Cài package (Debian / Ubuntu, qua `apt`)

`dpkg` phân biệt hai giai đoạn gỡ cài đặt:

```bash
# Gỡ mềm: dừng service, xóa binary / unit / man page,
# nhưng GIỮ LẠI /etc/pamsignal/pamsignal.conf để lần cài lại sau
# vẫn có thông tin xác thực và cài đặt điều chỉnh của bạn.
sudo apt remove pamsignal

# Gỡ cứng: dừng service VÀ xóa /etc/pamsignal/. Dùng khi
# bạn thực sự muốn loại bỏ hoàn toàn pamsignal khỏi host.
sudo apt purge pamsignal
```

Các đoạn script do debhelper sinh ra trong maintainer script của package sẽ stop unit khi gỡ, chạy `daemon-reload`, và xóa trạng thái enable của unit khi `purge`; cũng khi `purge`, `debian/pamsignal.postrm` còn xóa `/etc/pamsignal/`, kể cả các file bạn tự thêm vào đó. System user `pamsignal` **được cố ý giữ lại** qua cả `remove` và `purge`. Nếu có bất kỳ file nào trên hệ thống được tạo với UID đó (artifact runtime, file sót lại bất ngờ) mà user bị xóa, file sẽ bị orphan với UID số mà kernel có thể sau này tái sử dụng cho một user khác. Chỉ xóa user thủ công sau khi bạn đã xác nhận không có gì trên hệ thống thuộc sở hữu của nó:

```bash
sudo find / -user pamsignal 2>/dev/null
sudo userdel pamsignal     # chỉ khi lệnh find trên không trả về gì
```

### Cài package (Fedora / RHEL / AlmaLinux / Rocky, qua `dnf`)

rpm chỉ có một lệnh gỡ cài đặt:

```bash
sudo dnf remove pamsignal
```

Không có tương đương với `apt purge`: `dnf remove` đã xóa mọi thứ package đặt trên đĩa. Một điểm tinh tế: nếu bạn đã chỉnh sửa `/etc/pamsignal/pamsignal.conf` sau khi cài đặt, `rpm` sẽ lưu bản sửa đổi của bạn dưới tên `/etc/pamsignal/pamsignal.conf.rpmsave` thay vì xóa nó (chỉ thị `%config(noreplace)` trong `pamsignal.spec`). Xóa file `.rpmsave` bằng tay nếu bạn không còn cần cấu hình cũ.

Các block `%preun` / `%postun` trong spec xử lý vòng đời systemd. User `pamsignal` được giữ lại khi gỡ cài đặt vì lý do tương tự giải thích ở trên.

### Source build (`meson install`)

Nếu bạn đã chạy `sudo meson install -C build` thay vì cài package, không có cơ sở dữ liệu package manager nào theo dõi những gì đã được đặt ở đâu, nên bạn phải hoàn tác thủ công:

```bash
sudo systemctl stop pamsignal
sudo systemctl disable pamsignal
sudo rm /usr/local/bin/pamsignal
sudo rm /usr/local/lib/systemd/system/pamsignal.service
sudo rm -f /usr/local/share/man/man8/pamsignal.8
sudo rm -f /usr/local/share/man/man5/pamsignal.conf.5
sudo rm -rf /usr/local/etc/pamsignal
# Chỉ thị ConfigurationDirectory=pamsignal của systemd tự động tạo
# /etc/pamsignal/ khi unit khởi động lần đầu bất kể --prefix; với
# dev install dùng --prefix=/usr/local thư mục này rỗng và
# không được dùng nhưng vẫn bị để lại trừ khi xóa thủ công.
sudo rm -rf /etc/pamsignal
sudo userdel pamsignal
sudo systemctl daemon-reload
```

`/run/pamsignal/` không cần dọn dẹp thủ công: `RuntimeDirectory=pamsignal` tự xóa nó khi service dừng.

Nếu bạn đã cấu hình lại build với `--prefix=/usr --sysconfdir=/etc` để phản chiếu bố cục package, hãy thay `/usr/local/bin`, `/usr/local/lib/systemd/system`, `/usr/local/share/man/man8`, `/usr/local/share/man/man5` và `/usr/local/etc/pamsignal` bằng các đường dẫn `/usr/...` và `/etc/...` tương ứng.

## Hardening bảo mật

Unit đi kèm (`pamsignal.service.in`) đặt các chỉ thị service và bảo mật sau. `systemd-analyze security pamsignal.service` cho biết điểm exposure tương ứng; release workflow sẽ fail nếu điểm này vượt quá 2.0 (ngưỡng nội bộ 20).

| Chỉ thị | Tác dụng |
|-----------|--------|
| `Type=notify`, `NotifyAccess=main` | Unit chỉ được coi là đã start sau khi daemon gửi `READY=1`, tức là khi journal watch đã sẵn sàng |
| `WatchdogSec=30s` | Vòng lặp chính ping watchdog; nếu bị treo 30 giây, systemd kill và khởi động lại daemon |
| `ExecStart=/usr/bin/pamsignal --foreground` | Chạy ở foreground dưới systemd (đường dẫn theo install prefix) |
| `Restart=on-failure`, `RestartSec=5` | Khởi động lại sau 5 giây nếu crash |
| `ExecReload=/bin/kill -HUP $MAINPID` | `systemctl reload` gửi SIGHUP |
| `User=pamsignal`, `Group=pamsignal` | Chạy với user không có quyền đặc biệt |
| `SupplementaryGroups=systemd-journal` | Quyền đọc system journal |
| `Environment=PATH=/usr/bin:/bin` | `PATH` tối thiểu (curl vẫn được gọi bằng đường dẫn tuyệt đối) |
| `RuntimeDirectory=pamsignal` | Tạo `/run/pamsignal/` (PID file), xóa khi dừng |
| `ConfigurationDirectory=pamsignal` | Tạo `/etc/pamsignal/` |
| `NoNewPrivileges=yes` | Không thể nhận thêm quyền mới |
| `ProtectSystem=strict` | Filesystem ở chế độ chỉ đọc |
| `ProtectHome=yes` | Ẩn các thư mục home |
| `PrivateTmp=yes` | Mount `/tmp` riêng tư |
| `ProtectKernelTunables=yes` | `/proc/sys` và `/sys` ở chế độ chỉ đọc |
| `ProtectKernelModules=yes` | Không thể nạp kernel module |
| `ProtectKernelLogs=yes` | Không thể đọc kernel log buffer |
| `ProtectControlGroups=yes` | Cây cgroup ở chế độ chỉ đọc |
| `MemoryDenyWriteExecute=yes` | Không có vùng nhớ vừa ghi được vừa thực thi được (W^X) |
| `RestrictNamespaces=yes` | Không thể tạo namespace |
| `RestrictRealtime=yes` | Không thể dùng realtime scheduling |
| `RestrictSUIDSGID=yes` | Không thể đặt bit SUID/SGID |
| `LockPersonality=yes` | Không thể thay đổi execution domain |
| `PrivateDevices=yes` | Không có quyền truy cập vào thiết bị vật lý |
| `DevicePolicy=closed` | Chỉ các pseudo-device chuẩn (`null`, `zero`, `random`, ...) |
| `CapabilityBoundingSet=` | Tất cả capability bị bỏ |
| `SystemCallFilter=@system-service` và `~@privileged @resources` | Chỉ các syscall thuộc system-service, trừ nhóm privileged và resource-control |
| `SystemCallArchitectures=native` | Chỉ ABI syscall gốc (không có entry point compat 32-bit) |
| `ProtectClock=yes` | Không thể đổi đồng hồ hệ thống |
| `ProtectHostname=yes` | Không thể đổi hostname |
| `ProtectProc=invisible`, `ProcSubset=pid` | Ẩn process của user khác và các mục `/proc` không thuộc process |
| `RemoveIPC=yes` | Xóa các đối tượng SysV IPC của service user khi dừng |
| `RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6` | Chỉ local socket, netlink và IPv4/IPv6 (cho tiến trình con curl) |
| `UMask=0077` | File do daemon tạo ra chỉ owner mới truy cập được |
