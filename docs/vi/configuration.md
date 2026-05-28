# Configuration

> 🌐 [English](../configuration.md) · **Tiếng Việt**

`/etc/pamsignal/pamsignal.conf` — định dạng INI, không phụ thuộc thư viện ngoài. Tất cả các giá trị đều là tùy chọn; nếu file bị thiếu hoặc một key không có mặt, các giá trị mặc định hợp lý sẽ được áp dụng.

Vì file này có thể chứa thông tin xác thực của các kênh cảnh báo, quyền truy cập cần được giới hạn:

```bash
sudo chown root:pamsignal /etc/pamsignal/pamsignal.conf
sudo chmod 0640 /etc/pamsignal/pamsignal.conf
```

## Tham chiếu đầy đủ

```ini
# Brute-force detection
fail_threshold = 5
fail_window_sec = 300
max_tracked_ips = 256
alert_cooldown_sec = 60

# Chat-dispatch filter (default: all)
enable_notification_type = all

# Telegram
telegram_bot_token = <bot_token>
telegram_chat_id = <chat_id>

# Slack
slack_webhook_url = <webhook_url>

# Microsoft Teams
teams_webhook_url = <webhook_url>

# WhatsApp (Meta Cloud API)
whatsapp_access_token = <access_token>
whatsapp_phone_number_id = <phone_number_id>
whatsapp_recipient = <recipient_number>

# Discord
discord_webhook_url = <webhook_url>

# Custom webhook
webhook_url = <webhook_url>

# Custom webhook authentication (optional)
webhook_auth_header = Authorization: Bearer <token>

# Custom webhook mTLS (optional, advanced)
webhook_client_cert = /etc/pamsignal/webhook-client.crt
webhook_client_key  = /etc/pamsignal/webhook-client.key
webhook_ca_bundle   = /etc/pamsignal/webhook-ca.pem
```

## Phát hiện brute-force

| Key | Mặc định | Khoảng giá trị | Mô tả |
|-----|---------|-------|-------------|
| `fail_threshold` | `5` | 1 - 10000 | Số lần thất bại trước khi kích hoạt cảnh báo |
| `fail_window_sec` | `300` | 1 - 86400 | Cửa sổ thời gian (giây) để đếm số lần thất bại theo IP |
| `max_tracked_ips` | `256` | 1 - 100000 | Số IP tối đa được theo dõi cùng lúc |
| `alert_cooldown_sec` | `60` | 0 - 86400 | Số giây tối thiểu giữa các cảnh báo cho cùng một IP (0 = không có cooldown) |

## Bộ lọc loại thông báo

`enable_notification_type` cho phép chọn những loại sự kiện nào sẽ kích hoạt cảnh báo trên các kênh chat. Đây là danh sách phân cách bằng dấu phẩy. Mặc định — khi key bị bỏ qua hoặc khi `all` được chỉ định — là mọi loại sự kiện, giữ nguyên hành vi trước đó. Các token không hợp lệ là lỗi config cứng; giá trị rỗng và các phần tử danh sách rỗng đều bị từ chối.

| Token | Kích hoạt cảnh báo chat khi… |
|-------|---------------------------|
| `login_success` | Phát hiện đăng nhập thành công (sshd, login) |
| `login_failed` | Phát hiện đăng nhập thất bại (sshd, login; lỗi sudo/su vẫn chịu sự chặn lọc riêng theo từng sự kiện — xem bên dưới) |
| `session_open` | Một PAM session mở ra (bao gồm cả các session nền của systemd như cron) |
| `session_close` | Một PAM session đóng lại |
| `brute_force` | Ngưỡng brute-force từ xa (theo IP) hoặc nội bộ (theo actor sudo/su) bị vượt qua |
| `all` | Sentinel cho tất cả các loại ở trên (tương đương với việc bỏ qua key) |

**Phạm vi áp dụng.** Bộ lọc này chỉ kiểm soát việc gửi cảnh báo qua chat (Telegram, Slack, Teams, WhatsApp, Discord, custom webhook). Nhật ký cục bộ qua `journalctl -t pamsignal` vẫn ghi lại mọi sự kiện bất kể cài đặt, nên log forensics luôn đầy đủ. Cơ chế chặn riêng theo từng sự kiện cho `LOGIN_FAILED` của sudo/su (chỉ cảnh báo brute-force tổng hợp mới được gửi) là độc lập và nằm bên dưới bộ lọc này.

Ví dụ:

```ini
# Chỉ đăng nhập thành công và phát hiện brute-force
enable_notification_type = login_success,brute_force

# Chỉ brute-force
enable_notification_type = brute_force

# Tất cả (mặc định)
enable_notification_type = all
```

## Các kênh cảnh báo

Chỉ cấu hình những kênh bạn sử dụng. PAMSignal gửi cảnh báo đến tất cả các kênh đã có thông tin xác thực. Cảnh báo là best-effort — nếu một kênh bị lỗi, pamsignal ghi log cảnh báo và tiếp tục giám sát.

Xem [Alerts](./alerts.md) để biết định dạng tin nhắn, hướng dẫn cài đặt và tham chiếu payload.

| Key | Kênh | Mô tả |
|-----|---------|-------------|
| `telegram_bot_token` | Telegram | Bot token từ [@BotFather](https://t.me/BotFather) |
| `telegram_chat_id` | Telegram | ID của chat, group hoặc channel |
| `slack_webhook_url` | Slack | Incoming webhook URL |
| `teams_webhook_url` | Teams | Incoming webhook URL |
| `whatsapp_access_token` | WhatsApp | Meta Cloud API access token |
| `whatsapp_phone_number_id` | WhatsApp | Phone Number ID từ dashboard |
| `whatsapp_recipient` | WhatsApp | Số điện thoại người nhận có mã quốc gia (ví dụ: `84901234567`) |
| `discord_webhook_url` | Discord | Webhook URL từ cài đặt channel |
| `webhook_url` | Custom | URL endpoint của bạn (nhận JSON POST) |

## Xác thực custom webhook

Kênh `webhook_url` hỗ trợ hai cơ chế xác thực bổ sung tùy chọn — có thể dùng không cái nào, một trong hai, hoặc cả hai. Telegram, Slack, Teams, WhatsApp và Discord tự xác thực qua URL/token riêng của chúng và không bị ảnh hưởng.

| Key | Chế độ | Mô tả |
|-----|------|-------------|
| `webhook_auth_header` | Header | Một HTTP header tùy ý gửi kèm theo mỗi POST. Dạng đầy đủ `Name: value` để hỗ trợ mọi scheme xác thực (Bearer, API key, Splunk HEC, Datadog, HMAC). Giá trị được đưa vào một curl `-K` config file backed bởi memfd, nên secret không bao giờ xuất hiện trong `argv` hay `/proc/<pid>/cmdline`. |
| `webhook_client_cert` | mTLS | Đường dẫn đến client certificate mã hóa PEM. Phải được đặt cùng với `webhook_client_key`. |
| `webhook_client_key` | mTLS | Đường dẫn đến private key PEM tương ứng. **Không được phép đọc bởi group hoặc other** — pamsignal sẽ từ chối khởi động nếu vi phạm. Khuyến nghị: `0640 root:pamsignal` (hoặc `0600 pamsignal:pamsignal` nếu chạy daemon dưới user đó). |
| `webhook_ca_bundle` | mTLS | Đường dẫn tùy chọn đến CA bundle PEM. Chỉ cần khi CA của receiver không có trong system trust store (CA nội bộ, internal cert-manager). |

**Các pattern thường dùng:**

```ini
# Chỉ Bearer — hầu hết các receiver (Wazuh, Splunk HEC, Datadog, custom Express receivers).
webhook_url = https://siem.example.com/ingest/pamsignal
webhook_auth_header = Authorization: Bearer <token>

# Chỉ mTLS — môi trường đã có PKI; xác thực danh tính service ở tầng transport.
webhook_url = https://siem.internal.example.com/ingest
webhook_client_cert = /etc/pamsignal/webhook-client.crt
webhook_client_key  = /etc/pamsignal/webhook-client.key

# Kết hợp — SIEM gateway doanh nghiệp yêu cầu cả transport auth lẫn per-request authorization.
webhook_url = https://siem.internal.example.com/ingest
webhook_auth_header = Authorization: Bearer <jwt>
webhook_client_cert = /etc/pamsignal/webhook-client.crt
webhook_client_key  = /etc/pamsignal/webhook-client.key
webhook_ca_bundle   = /etc/pamsignal/internal-ca.pem
```

*Bất kỳ pattern nào trong số này đều có thể kết hợp với `enable_notification_type` để thu hẹp loại sự kiện nào được gửi đến webhook — xem [Bộ lọc loại thông báo](#bộ-lọc-loại-thông-báo) ở trên để biết danh sách đầy đủ các token (`login_success`, `login_failed`, `session_open`, `session_close`, `brute_force`, `all`).*

**Các kiểm tra xác thực được thực thi khi load config:**

- Đặt bất kỳ key TLS nào trong ba key mà không có `webhook_url` là lỗi load config.
- `webhook_client_cert` và `webhook_client_key` phải được đặt cùng nhau; thiếu một trong hai sẽ bị từ chối.
- Tất cả đường dẫn cert/key/CA đều được mở với `O_NOFOLLOW` (symlink bị từ chối) và phải là file thường thuộc sở hữu của `root` hoặc daemon user.
- Các chuỗi đường dẫn chứa ký tự điều khiển, `"` hoặc `\` đều bị từ chối để đảm bảo giá trị rõ ràng trong curl `-K` config.
- `webhook_auth_header` phải ở dạng `Name: value`; các giá trị chứa CR, LF, `"` hoặc `\` đều bị từ chối (bảo vệ chống CRLF header injection / quote-escape).

Khóa mã hóa (protected bằng passphrase) không được hỗ trợ — hãy quản lý bí mật của key thông qua quyền filesystem, `systemd-creds`, hoặc mô hình secret injection của cert manager.

Xem [Alerts → Custom webhook (ECS JSON)](./alerts.md#custom-webhook-ecs-json) để biết payload truyền qua mạng, bảng các pattern receiver (Bearer / X-API-Key / Splunk / Datadog / Wazuh), và hướng dẫn triển khai mTLS phía operator.

## CLI flags

| Flag | Viết tắt | Mô tả |
|------|-------|-------------|
| `--foreground` | `-f` | Chạy ở chế độ foreground (không daemonize) |
| `--config PATH` | `-c PATH` | Sử dụng file config ở đường dẫn tùy chỉnh |

Đường dẫn tương đối sẽ được chuyển thành đường dẫn tuyệt đối trước khi daemonize.

## Reload không cần restart

```bash
sudo systemctl reload pamsignal
```

Lệnh này gửi SIGHUP đến daemon. Nếu config mới hợp lệ, nó có hiệu lực ngay lập tức và bảng theo dõi brute-force sẽ được reset. Nếu config có lỗi, daemon giữ nguyên config hiện tại và ghi log cảnh báo.
