# PAMSignal Node.js Webhook Receiver

> [English](../../../examples/nodejs-webhook/README.md) · **Tiếng Việt**

Đây là ví dụ sẵn dùng về một Custom Webhook receiver được xây dựng bằng **TypeScript**, Node.js và Express. Receiver nhận các ECS JSON alert có cấu trúc từ PAMSignal và xử lý chúng.

Ví dụ này áp dụng các best practice của Express, bao gồm:
- **TypeScript** để đảm bảo type safety nghiêm ngặt và cú pháp hiện đại
- **Security Headers** sử dụng `helmet`
- **Request Logging** sử dụng `morgan`
- **Authentication** bằng Bearer token bí mật

## Bắt đầu

### 1. Cài đặt Dependencies

Đảm bảo bạn đã cài Node.js 20 trở lên và [pnpm](https://pnpm.io/installation), sau đó chạy:

```bash
pnpm install
```

Hãy dùng pnpm thay vì npm: lockfile là `pnpm-lock.yaml`, và các security override cho dependency gián tiếp có lỗ hổng nằm trong `pnpm-workspace.yaml`, thứ mà npm bỏ qua.

### 2. Cấu hình Environment

Sao chép file environment mẫu và đặt một secret token mạnh:

```bash
cp .env.example .env
```

Chỉnh sửa `.env` và đặt `WEBHOOK_SECRET` thành một chuỗi ngẫu nhiên.

### 3. Build & Chạy Server

```bash
# Compile TypeScript sang JavaScript (xuất ra thư mục dist/)
pnpm run build

# Chạy code đã compile cho môi trường production
pnpm start

# Để phát triển (tự khởi động lại khi file thay đổi, không cần build)
pnpm run dev
```

Server sẽ bắt đầu lắng nghe tại `http://localhost:3000/webhook/pamsignal`.

## Tích hợp với PAMSignal

Express app này bắt buộc sử dụng `Authorization: Bearer <token>` để tránh lộ secret qua access log của URL. PAMSignal hỗ trợ điều này trực tiếp thông qua config key `webhook_auth_header`, không cần reverse proxy.

PAMSignal chỉ gửi qua HTTPS: `webhook_url` phải bắt đầu bằng `https://` (nếu không, config bị từ chối) và curl chạy với `--proto =https`. Chế độ plain HTTP ở trên chỉ dùng để thử bằng curl và Bruno. Với alert thật, hãy chạy receiver với TLS (xem [Mutual TLS](#mutual-tls-nâng-cao)) hoặc đặt sau một TLS reverse proxy.

### Cấu hình trực tiếp (khuyến nghị)

Chỉnh sửa `/etc/pamsignal/pamsignal.conf`:

```ini
webhook_url = https://your-receiver.example.com/webhook/pamsignal
webhook_auth_header = Authorization: Bearer your_super_secret_token_here
```

Reload PAMSignal để áp dụng các thay đổi:

```bash
sudo systemctl reload pamsignal
```

Sau đó kiểm tra kênh từ đầu đến cuối. `--test-alert` gửi một payload `test_alert` tới mọi kênh đã cấu hình và báo `ok` hoặc `FAILED` cho từng kênh; receiver sẽ ghi một dòng `[TEST_ALERT]`:

```bash
sudo -u pamsignal pamsignal --test-alert
```

Giá trị header được truyền cho curl qua một memfd-backed config file, vì vậy token không bao giờ xuất hiện trong `/proc/<pid>/cmdline`. Đặt quyền `0640 root:pamsignal` trên `pamsignal.conf` để giữ giá trị không đọc được từ disk với các user không phải daemon.

### Reverse proxy (thay thế)

Nếu bạn đã đặt receiver phía sau Nginx/Caddy/Traefik (TLS termination, rate-limit, v.v.), bạn có thể để proxy inject header thay thế:

- Proxy: `proxy_set_header Authorization "Bearer your_super_secret_token_here";`
- pamsignal.conf: `webhook_url = https://your-secure-proxy.local/webhook/pamsignal` (bỏ qua `webhook_auth_header`)

### Mutual TLS (nâng cao)

Nếu bạn đã vận hành một internal PKI, ví dụ này có thể chạy như một HTTPS receiver thực thi mTLS, kết hợp với config `webhook_client_cert` / `webhook_client_key` của pamsignal. Server tự động chọn HTTPS thay vì plain HTTP khi các TLS env var được thiết lập.

#### Demo end-to-end cục bộ

```bash
# 1. Generate a CA + server cert + client cert in the shared dir.
#    The `./certs/` path here is a symlink to ../shared-certs/, so the
#    Python example and the Bruno collection pick up the same files.
(cd ../shared-certs && ./gen-test-certs.sh)

# 2. Configure this example to listen on HTTPS and require a client cert.
cat >> .env <<'EOF'
TLS_KEY_PATH=./certs/server.key
TLS_CERT_PATH=./certs/server.crt
TLS_CLIENT_CA_PATH=./certs/ca.crt
TLS_REQUIRE_CLIENT_CERT=true
EOF

# 3. Start the receiver.
pnpm run dev   # or: pnpm run build && pnpm start
```

Bạn sẽ thấy `PAMSignal Webhook Receiver listening on https://localhost:3000/webhook/pamsignal (mTLS, client cert required)`.

#### Cấu hình pamsignal

Trong `/etc/pamsignal/pamsignal.conf`:

```ini
webhook_url = https://localhost:3000/webhook/pamsignal
webhook_auth_header = Authorization: Bearer your_super_secret_token_here
webhook_client_cert = /etc/pamsignal/webhook-client.crt
webhook_client_key  = /etc/pamsignal/webhook-client.key
# Required because the demo CA isn't in the system trust store.
webhook_ca_bundle   = /etc/pamsignal/webhook-ca.crt
```

PAMSignal sẽ không dùng trực tiếp các file trong `./certs/`: nó mở từng đường dẫn với `O_NOFOLLOW` (symlink bị từ chối), mỗi file phải thuộc sở hữu của `root` hoặc user của daemon, key không được để group hoặc world đọc, và `ProtectHome=yes` của unit ẩn `/home`. Hãy sao chép chúng vào đúng chỗ, với key thuộc sở hữu của `pamsignal` vì curl chạy dưới user đó:

```bash
sudo install -m 0644 -o root -g root certs/client.crt /etc/pamsignal/webhook-client.crt
sudo install -m 0644 -o root -g root certs/ca.crt     /etc/pamsignal/webhook-ca.crt
sudo install -m 0600 -o pamsignal -g pamsignal certs/client.key /etc/pamsignal/webhook-client.key
sudo -u pamsignal pamsignal --check-config
```

Reload pamsignal (`sudo systemctl reload pamsignal`) rồi chạy `sudo -u pamsignal pamsignal --test-alert`; receiver sẽ ghi một dòng `[TEST_ALERT]`. Một request từ bất kỳ client nào không có cert hợp lệ (ví dụ: `curl https://localhost:3000/webhook/pamsignal`) sẽ bị từ chối ngay tại TLS handshake, trước khi đến được Express.

#### Cấu hình cho môi trường production

Cho các deployment trên môi trường production, hãy thay các file demo bằng file được quản lý bởi cert pipeline của bạn (cert-manager, certbot, `systemd-creds`, internal CA + ACME, v.v.). Bốn env var và các config key `webhook_*` không thay đổi. `gen-test-certs.sh` chỉ dùng cho kiểm thử local/CI, không đưa output của nó lên production.

mTLS kết hợp cộng thêm với `webhook_auth_header` nếu receiver muốn cả hai (mTLS để xác minh danh tính service ở transport layer, Bearer để ủy quyền từng request). Express middleware trong ví dụ này kiểm tra Bearer token bất kể transport, vì vậy một deployment chỉ dùng mTLS có thể đơn giản để `WEBHOOK_SECRET` trống (hoặc đặt cả hai để tăng cường bảo mật theo chiều sâu).

## PAMSignal gửi những gì

PAMSignal gửi một object ECS JSON cho mỗi alert. Receiver chỉ kiểm tra có `event` và `pamsignal`, sau đó ghi một dòng log theo `event.action`:

| `event.action` | Khi nào | Các trường dòng log sử dụng |
|---|---|---|
| `login_success` | Đăng nhập thành công | `user.name`, `source.ip`, `host.hostname`, `process.pid` |
| `login_failure` | Đăng nhập thất bại (lỗi `sudo`/`su` không được gửi từng lần; chúng chỉ được đếm cho brute force) | `user.name`, `source.ip`, `host.hostname` |
| `session_opened`, `session_closed` | Mở và đóng phiên | `user.name`, `host.hostname` |
| `brute_force_detected` | `fail_threshold` lần thất bại trong `fail_window_sec` | `pamsignal.attempts`, `source.ip`, `pamsignal.window_sec` |
| `login_after_failures` | Đăng nhập thành công ngay sau một chuỗi thất bại từ cùng IP | `user.name`, `source.ip`, `pamsignal.failures`, `host.hostname` |
| `test_alert` | `pamsignal --test-alert` | `host.hostname` |

Action khác được ghi là `[UNKNOWN_EVENT]`. Có hai dạng payload cần lưu ý nếu bạn mở rộng handler:

- Sự kiện phiên không có object `source`. Khi phiên được mở từ một tài khoản khác (ví dụ một phiên `sudo` do `alice` khởi chạy), `pamsignal.actor` chứa tài khoản đó và `user.name` vẫn là user của phiên.
- Brute force `sudo`/`su` cục bộ không có object `source`: `user.name` là tài khoản đang gõ mật khẩu và `user.target.name` là tài khoản nó muốn chuyển sang. Dòng log demo in `source.ip`, nên sẽ hiện `undefined` trong trường hợp này.

Ví dụ payload đầy đủ và bảng tham chiếu trường nằm ở [docs/alerts.md](../alerts.md#custom-webhook-ecs-json).

## Triển khai như Systemd Daemon

Để chạy trên production, bạn nên chạy webhook receiver này như một background service để nó tự động khởi động khi boot và khởi động lại nếu bị crash.

1. Đảm bảo bạn đã compile code:
   ```bash
   pnpm run build
   ```

2. Tạo một systemd service file. Mở `/etc/systemd/system/pamsignal-webhook.service`:
   ```bash
   sudo nano /etc/systemd/system/pamsignal-webhook.service
   ```

3. Dán cấu hình sau đây. Hãy chắc chắn cập nhật `WorkingDirectory` thành đường dẫn thực tế của project và `User` thành user non-root thực tế của bạn:

   ```ini
   [Unit]
   Description=PAMSignal Node.js Webhook Receiver
   After=network.target

   [Service]
   Type=simple
   # Update this to the user you want to run the Node.js process as
   User=www-data
   # Update this to the absolute path of this example directory
   WorkingDirectory=/opt/pamsignal-nodejs-webhook
   # Path to your Node.js executable (find it with `which node`)
   ExecStart=/usr/bin/node dist/server.js
   Restart=on-failure
   RestartSec=5
   
   # Load the environment variables from the .env file
   EnvironmentFile=/opt/pamsignal-nodejs-webhook/.env

   # Security Hardening
   NoNewPrivileges=yes
   ProtectSystem=strict
   ProtectHome=yes
   PrivateTmp=yes

   [Install]
   WantedBy=multi-user.target
   ```

4. Bật và khởi động service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now pamsignal-webhook
   sudo systemctl status pamsignal-webhook
   ```

5. Xem log theo thời gian thực:
   ```bash
   journalctl -u pamsignal-webhook -f
   ```

## Kiểm thử thủ công

### Dùng Bruno API Client

Một **Bruno** collection dùng chung nằm tại [`../../../examples/bruno-collection/`](../../../examples/bruno-collection/) và hoạt động với bất kỳ receiver nào triển khai PAMSignal webhook contract. Ví dụ Node.js này và ví dụ Python Flask đều đủ điều kiện. Collection đi kèm hai environment:

- **Local**: plain HTTP, chỉ dùng Bearer token
- **Local-mTLS**: HTTPS với client cert (kết hợp với `TLS_REQUIRE_CLIENT_CERT=true` ở đây)

Xem [`bruno-collection.md`](bruno-collection.md) để biết cách thiết lập cert symlink. Bắt đầu nhanh:

1. Tải [Bruno](https://www.usebruno.com/).
2. Click **Open Collection** (không phải *Import Collection*, vốn dùng cho Postman/OpenAPI JSON) và chọn thư mục `examples/bruno-collection`.
3. Chọn environment từ dropdown (góc trên bên phải): `Local` hoặc `Local-mTLS`.
4. Cập nhật `WEBHOOK_SECRET` của environment đã chọn để khớp với `.env` của bạn và click **Send**.

### Dùng Curl

Bạn cũng có thể mô phỏng một PAMSignal brute-force alert bằng `curl` để kiểm thử Express server. Receiver chỉ kiểm tra có `event` và `pamsignal`, nên một payload rút gọn là đủ:

```bash
# Testing with Bearer Token header
curl -X POST http://localhost:3000/webhook/pamsignal \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer your_super_secret_token_here" \
     -d '{
       "event": { "action": "brute_force_detected" },
       "source": { "ip": "203.0.113.50" },
       "pamsignal": { "attempts": 12, "window_sec": 300 }
     }'
```

Receiver ghi `[BRUTE_FORCE] 12 failed attempts detected from IP 203.0.113.50 in 300s!` ra console (hoặc `journalctl -u pamsignal-webhook` khi chạy như service).

## Unit Tests

Project này bao gồm một bộ Jest test kiểm tra xác thực (Bearer token), payload validation, một vòng request HTTP thật, và đường dẫn mTLS handshake.

Để chạy tests:

```bash
pnpm test
```
