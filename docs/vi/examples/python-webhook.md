# PAMSignal Python Webhook Receiver

> 🌐 [English](../../../examples/python-webhook/README.md) · **Tiếng Việt**

Đây là ví dụ sẵn dùng về một Custom Webhook receiver được xây dựng bằng **Python** và **Flask**. Receiver nhận các ECS JSON alert có cấu trúc từ PAMSignal và xử lý chúng. Đây là phiên bản Python tương đương với ví dụ `examples/nodejs-webhook/` và cung cấp cùng endpoint contract, env var, và hành vi mTLS.

Ví dụ này bao gồm:
- **Flask** cho HTTP layer
- **Authentication** bằng Bearer token bí mật (không lộ secret qua URL)
- Tùy chọn **HTTPS / mutual TLS** khi kết hợp với `webhook_client_cert` / `webhook_client_key` trong `pamsignal.conf`
- **[uv](https://docs.astral.sh/uv/)** để quản lý dependency và virtualenv

## 🚀 Bắt đầu

### 1. Cài đặt uv

Nếu bạn chưa có:

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Xem [tài liệu cài đặt uv](https://docs.astral.sh/uv/getting-started/installation/) để biết các phương pháp khác.

### 2. Cài đặt Dependencies

Từ thư mục này:

```bash
uv sync
```

`uv sync` tạo `.venv/` và cài đặt mọi thứ từ `pyproject.toml` (bao gồm cả các dev tool như `pytest`).

### 3. Cấu hình Environment

Sao chép file environment mẫu và đặt một secret token mạnh:

```bash
cp .env.example .env
```

Chỉnh sửa `.env` và đặt `WEBHOOK_SECRET` thành một chuỗi ngẫu nhiên (ví dụ: `openssl rand -hex 32`).

### 4. Chạy Server

```bash
uv run python src/server.py
```

Server sẽ bắt đầu lắng nghe tại `http://localhost:3000/webhook/pamsignal`.

## ⚙️ Tích hợp với PAMSignal

Flask app này bắt buộc sử dụng `Authorization: Bearer <token>` để tránh lộ secret qua access log của URL. PAMSignal hỗ trợ điều này trực tiếp thông qua config key `webhook_auth_header` — không cần reverse proxy.

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
#    Node example and the Bruno collection pick up the same files.
(cd ../shared-certs && ./gen-test-certs.sh)

# 2. Configure this example to listen on HTTPS and require a client cert.
cat >> .env <<'EOF'
TLS_KEY_PATH=./certs/server.key
TLS_CERT_PATH=./certs/server.crt
TLS_CLIENT_CA_PATH=./certs/ca.crt
TLS_REQUIRE_CLIENT_CERT=true
EOF

# 3. Start the receiver.
uv run python src/server.py
```

Bạn sẽ thấy `🔐 PAMSignal Webhook Receiver listening on https://localhost:3000/webhook/pamsignal (mTLS — client cert required)`.

#### Cấu hình pamsignal

Trong `/etc/pamsignal/pamsignal.conf`:

```ini
webhook_url = https://localhost:3000/webhook/pamsignal
webhook_auth_header = Authorization: Bearer your_super_secret_token_here
webhook_client_cert = /absolute/path/to/certs/client.crt
webhook_client_key  = /absolute/path/to/certs/client.key
# Required because the demo CA isn't in the system trust store.
webhook_ca_bundle   = /absolute/path/to/certs/ca.crt
```

Reload pamsignal (`sudo systemctl reload pamsignal`) và kích hoạt một event — receiver sẽ ghi log nó. Một request từ bất kỳ client nào không có cert hợp lệ (ví dụ: `curl https://localhost:3000/webhook/pamsignal`) sẽ bị từ chối ngay tại TLS handshake, trước khi đến được Flask.

#### Cấu hình cho môi trường production

Cho các deployment trên môi trường production, hãy thay `./certs/*` bằng các đường dẫn được quản lý bởi cert pipeline của bạn (cert-manager, certbot, `systemd-creds`, internal CA + ACME, v.v.). Bốn env var và các config key `webhook_*` không thay đổi. `gen-test-certs.sh` chỉ dùng cho kiểm thử local/CI — không đưa output của nó lên production.

mTLS kết hợp cộng thêm với `webhook_auth_header` nếu receiver muốn cả hai (mTLS để xác minh danh tính service ở transport layer, Bearer để ủy quyền từng request). Flask middleware trong ví dụ này kiểm tra Bearer token bất kể transport, vì vậy một deployment chỉ dùng mTLS có thể đơn giản để `WEBHOOK_SECRET` trống (hoặc đặt cả hai để tăng cường bảo mật theo chiều sâu).

## 🛠️ Triển khai như Systemd Daemon

Để chạy trên production, bạn nên chạy webhook receiver này như một background service để nó tự động khởi động khi boot và khởi động lại nếu bị crash. Server tích hợp sẵn của Werkzeug phù hợp cho webhook khối lượng thấp, nhưng với tải cao hơn bạn có thể muốn đặt một WSGI server thực (gunicorn, uWSGI) phía trước — điều chỉnh `ExecStart` cho phù hợp.

1. Cài đặt dependencies vào `.venv/` của project:
   ```bash
   uv sync --no-dev
   ```

2. Tạo một systemd service file. Mở `/etc/systemd/system/pamsignal-webhook.service`:
   ```bash
   sudo nano /etc/systemd/system/pamsignal-webhook.service
   ```

3. Dán cấu hình sau đây. Hãy chắc chắn cập nhật `WorkingDirectory` thành đường dẫn thực tế của project và `User` thành user non-root thực tế của bạn:

   ```ini
   [Unit]
   Description=PAMSignal Python Webhook Receiver
   After=network.target

   [Service]
   Type=simple
   # Update this to the user you want to run the Python process as
   User=www-data
   # Update this to the absolute path of this example directory
   WorkingDirectory=/opt/pamsignal-python-webhook
   # Run the server using the venv's Python interpreter
   ExecStart=/opt/pamsignal-python-webhook/.venv/bin/python src/server.py
   Restart=on-failure
   RestartSec=5

   # Load the environment variables from the .env file
   EnvironmentFile=/opt/pamsignal-python-webhook/.env

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

## 🧪 Kiểm thử thủ công

### Dùng Curl

Bạn có thể mô phỏng một PAMSignal brute-force alert bằng `curl` để kiểm thử Flask server:

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

Bạn sẽ thấy event được parse và ghi log đẹp trong stream `journalctl` hoặc console Python của bạn.

### Dùng Bruno API Client

Một **Bruno** collection dùng chung nằm tại [`../../../examples/bruno-collection/`](../../../examples/bruno-collection/) và hoạt động với bất kỳ receiver nào triển khai PAMSignal webhook contract — ví dụ Python này và ví dụ Node.js đều đủ điều kiện. Collection đi kèm hai environment:

- **Local** — plain HTTP, chỉ dùng Bearer token
- **Local-mTLS** — HTTPS với client cert (kết hợp với `TLS_REQUIRE_CLIENT_CERT=true` ở đây)

Xem [`bruno-collection.md`](bruno-collection.md) để biết cách thiết lập cert symlink. Bắt đầu nhanh:

1. Tải [Bruno](https://www.usebruno.com/).
2. Click **Open Collection** (không phải *Import Collection* — đường dẫn đó dùng cho Postman/OpenAPI JSON) và chọn thư mục `examples/bruno-collection`.
3. Chọn environment từ dropdown (góc trên bên phải) — `Local` hoặc `Local-mTLS`.
4. Cập nhật `WEBHOOK_SECRET` của environment đã chọn để khớp với `.env` của bạn và click **Send**.

## ✅ Unit Tests

Project này bao gồm một bộ `pytest` test kiểm tra xác thực (Bearer token), payload validation và đường dẫn mTLS handshake.

Để chạy tests:

```bash
uv run pytest
```

Các mTLS test yêu cầu `openssl` phải có trong `PATH` (dùng để generate cert tạm thời trong một thư mục tạm); chúng sẽ tự động bị bỏ qua nếu không tìm thấy.
