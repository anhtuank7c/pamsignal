# Alerts

> 🌐 [English](../alerts.md) · **Tiếng Việt**

PAMSignal gửi cảnh báo best-effort đến các nền tảng nhắn tin khi phát hiện sự kiện đăng nhập hoặc pattern brute-force. Cảnh báo được gửi qua `fork()+exec(curl)` — một tiến trình con tồn tại trong thời gian ngắn, không thể ảnh hưởng đến quá trình giám sát cốt lõi.

Nếu một cảnh báo thất bại (mạng bị ngắt, lỗi API, timeout), pamsignal ghi log cảnh báo và tiếp tục. Sự kiện luôn được ghi vào journal trước tiên.

## Các kênh hỗ trợ

| Kênh | Các config key cần có |
|---------|-------------------|
| Telegram | `telegram_bot_token`, `telegram_chat_id` |
| Slack | `slack_webhook_url` |
| Microsoft Teams | `teams_webhook_url` |
| WhatsApp | `whatsapp_access_token`, `whatsapp_phone_number_id`, `whatsapp_recipient` |
| Discord | `discord_webhook_url` |
| Custom webhook | `webhook_url` |

Chỉ cấu hình những kênh bạn sử dụng. PAMSignal gửi đến tất cả các kênh đã có thông tin xác thực. Xem [Configuration](./configuration.md) để biết tham chiếu config đầy đủ.

## Định dạng tin nhắn

Kể từ v0.2.0, các payload cảnh báo tuân theo quy ước [Elastic Common Schema (ECS)]:

- **Các kênh chat** (Telegram / Slack / Teams / WhatsApp / Discord) nhận tin nhắn văn bản một dòng, có tiền tố severity dạng `key=value`.
- **Custom webhook** nhận một JSON document với các object ECS lồng nhau (`event.*`, `host.*`, `user.*`, `source.*`, `service.*`, `process.*`) cộng với namespace `pamsignal.*` cho các trường riêng của vendor.

Điều này có nghĩa là output của webhook có thể đưa thẳng vào Elastic SIEM và Wazuh mà không cần remapping, và chỉ cần một config Vector / Logstash để kết nối với bất kỳ SIEM hiện đại nào khác.

[Elastic Common Schema (ECS)]: https://www.elastic.co/guide/en/ecs/current/index.html

### Định dạng văn bản chat

Dấu ngoặc severity có độ rộng cố định (8 ký tự) để các cột thẳng hàng khi hiển thị monospace. Thứ tự trường là severity → action → identity → location → metadata → `pid` → `ts`. Trường `pid=` là tiến trình đang chạy cho các sự kiện `session_opened` và `login_success` (bạn có thể `kill <pid>` để ngắt kết nối người dùng) và là auth child đã kết thúc cho các trường hợp thất bại (đã được thu hồi — chỉ hữu ích như thông tin forensics).

```
[INFO]   auth.session_opened user=root host=web-01 service=sudo pid=12345 ts=2026-03-29T14:23:01+0000 provider=aws service_name=web-api
[INFO]   auth.session_closed user=root host=web-01 service=sshd pid=12346 ts=2026-03-29T14:25:10+0000 provider=aws service_name=web-api
[NOTICE] auth.login_success user=admin src=192.168.1.100:52341 host=web-01 service=sshd auth=password pid=12345 ts=2026-03-29T14:23:01+0000
[WARN]   auth.login_failure user=root src=203.0.113.50:39182 host=web-01 service=sshd auth=password pid=12347 ts=2026-03-29T14:23:01+0000
[ALERT]  auth.brute_force_detected src=203.0.113.50 attempts=12 window=300s user=root host=web-01 pid=12347 ts=2026-03-29T14:23:01+0000
[ALERT]  auth.brute_force_detected actor=alice target=root attempts=5 window=300s service=sudo host=web-01 pid=12348 ts=2026-03-29T14:23:01+0000
```

Dạng cuối cùng được phát ra khi một user nội bộ (`alice`) liên tục thất bại khi xác thực qua `sudo`/`su` trên host. Không có `src=` vì thao tác không có remote endpoint; ECS `user.name` mang tên actor và `user.target.name` là mục tiêu leo thang quyền. Cảnh báo `auth.login_failure` theo từng sự kiện **không** được phát cho sudo/su — chỉ có cảnh báo brute-force tổng hợp mới được gửi, để một lần gõ sai mật khẩu không làm phiền operator. Tuy nhiên, bản ghi journal từ `pamsignal` vẫn được ghi cho mỗi lần thất bại riêng lẻ.

*(Lưu ý: Các tag context tùy chỉnh như `provider=aws service_name=web-api` sẽ tự động được thêm vào nếu được cấu hình trong `pamsignal.conf`)*

### Telegram

Gửi dưới dạng plain text qua [Bot API `sendMessage`](https://core.telegram.org/bots/api#sendmessage). Cùng định dạng văn bản chat một dòng như trên.

**Cài đặt:**
1. Tạo bot với [@BotFather](https://t.me/BotFather) và sao chép token
2. Thêm bot vào group/channel của bạn
3. Lấy chat ID (gửi một tin nhắn, sau đó kiểm tra `https://api.telegram.org/bot<token>/getUpdates`)
4. Đặt `telegram_bot_token` và `telegram_chat_id` trong `pamsignal.conf`

### Slack

Gửi dưới dạng tin nhắn một dòng qua [incoming webhook](https://api.slack.com/messaging/webhooks). Cùng định dạng văn bản chat.

**Cài đặt:**
1. Vào [Slack App Directory](https://api.slack.com/apps) và tạo một app
2. Bật **Incoming Webhooks** và tạo webhook cho channel của bạn
3. Đặt `slack_webhook_url` trong `pamsignal.conf`

### Microsoft Teams

Gửi dưới dạng plain text qua [incoming webhook connector](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook).

**Cài đặt:**
1. Trong Teams channel của bạn, vào **Channel settings > Connectors > Incoming Webhook**
2. Đặt `teams_webhook_url` trong `pamsignal.conf`

### WhatsApp

Gửi dưới dạng plain text qua [Meta WhatsApp Cloud API](https://developers.facebook.com/docs/whatsapp/cloud-api).

**Cài đặt:**
1. Tạo [Meta Business app](https://developers.facebook.com/apps/) và thêm WhatsApp
2. Lấy **Phone Number ID** và tạo **permanent access token**
3. Đặt `whatsapp_access_token`, `whatsapp_phone_number_id` và `whatsapp_recipient` trong `pamsignal.conf`

> **Lưu ý:** WhatsApp Cloud API yêu cầu tài khoản Meta Business đã xác minh cho mục đích sử dụng thực tế (production).

### Discord

Gửi dưới dạng plain text qua [Discord webhook](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks).

**Cài đặt:**
1. Trong Discord channel của bạn, vào **Settings > Integrations > Webhooks > New Webhook**
2. Đặt `discord_webhook_url` trong `pamsignal.conf`

### Custom webhook (ECS JSON)

Gửi dưới dạng request `POST` với `Content-Type: application/json`. Tuân theo ECS nên có thể đưa vào Elastic Stack, Wazuh, hoặc bất kỳ pipeline nào hỗ trợ ECS mà không cần remapping trường.

> 💡 **Muốn xây dựng receiver của riêng bạn?** Tham khảo **[Node.js Express Webhook Example](examples/nodejs-webhook.md)** sẵn sàng triển khai! Nó minh họa cách xác thực, phân tích cú pháp ECS JSON payload, và định tuyến các sự kiện PAMSignal.

**Sự kiện đăng nhập:**

```json
{
  "@timestamp": "2026-03-29T14:23:01+0000",
  "event": {
    "action": "login_failure",
    "category": ["authentication"],
    "kind": "event",
    "outcome": "failure",
    "severity": 5,
    "module": "pamsignal",
    "dataset": "pamsignal.events"
  },
  "host": {"hostname": "web-01"},
  "user": {"name": "root"},
  "service": {"name": "sshd"},
  "source": {"ip": "203.0.113.50", "port": 39182},
  "process": {"pid": 12347, "user": {"id": "0"}},
  "pamsignal": {
    "event_type": "LOGIN_FAILED",
    "auth_method": "password"
  },
  "labels": {
    "provider": "aws",
    "service_name": "database"
  }
}
```

*(Lưu ý: Object `labels` chỉ được đưa vào nếu bạn đã định nghĩa `provider` hoặc `service_name` trong `pamsignal.conf`)*

**Sự kiện session** (không có `source.*` vì đây không phải sự kiện mạng):

```json
{
  "@timestamp": "2026-03-29T14:23:01+0000",
  "event": {
    "action": "session_opened",
    "category": ["authentication", "session"],
    "kind": "event",
    "outcome": "success",
    "severity": 3,
    "module": "pamsignal",
    "dataset": "pamsignal.events"
  },
  "host": {"hostname": "web-01"},
  "user": {"name": "root"},
  "service": {"name": "sudo"},
  "process": {"pid": 12345, "user": {"id": "0"}},
  "pamsignal": {"event_type": "SESSION_OPEN"}
}
```

**Phát hiện brute-force — từ xa (sshd, hoặc sudo/su có `rhost=`)**: được đánh key theo source IP, `event.kind=alert`, severity 8:

```json
{
  "@timestamp": "2026-03-29T14:23:01+0000",
  "event": {
    "action": "brute_force_detected",
    "category": ["authentication", "intrusion_detection"],
    "kind": "alert",
    "outcome": "unknown",
    "severity": 8,
    "module": "pamsignal",
    "dataset": "pamsignal.events"
  },
  "host": {"hostname": "web-01"},
  "user": {"name": "root"},
  "source": {"ip": "203.0.113.50"},
  "process": {"pid": 12347},
  "pamsignal": {
    "event_type": "BRUTE_FORCE_DETECTED",
    "attempts": 12,
    "window_sec": 300
  }
}
```

**Phát hiện brute-force — nội bộ (sudo/su không có remote endpoint)**: được đánh key theo actor (`ruser=`), không có `source.*`. `user.name` là actor; `user.target.name` là mục tiêu leo thang quyền:

```json
{
  "@timestamp": "2026-03-29T14:23:01+0000",
  "event": {
    "action": "brute_force_detected",
    "category": ["authentication", "intrusion_detection"],
    "kind": "alert",
    "outcome": "unknown",
    "severity": 8,
    "module": "pamsignal",
    "dataset": "pamsignal.events"
  },
  "host": {"hostname": "web-01"},
  "user": {"name": "alice", "target": {"name": "root"}},
  "service": {"name": "sudo"},
  "process": {"pid": 12348},
  "pamsignal": {
    "event_type": "BRUTE_FORCE_DETECTED",
    "attempts": 5,
    "window_sec": 300
  }
}
```

**Chi tiết HTTP:**

| Thuộc tính | Giá trị |
|----------|-------|
| Method | `POST` |
| Content-Type | `application/json` |
| Response mong đợi | `2xx` (non-2xx được ghi log như cảnh báo) |

**Xác thực (tùy chọn):**

Đặt `webhook_auth_header` trong `pamsignal.conf` để gửi một HTTP header tùy ý kèm theo mỗi POST:

```ini
webhook_url = https://siem.example.com/ingest/pamsignal
webhook_auth_header = Authorization: Bearer s3cr3t-token-here
```

Các pattern phổ biến:

| Receiver | Header |
|----------|--------|
| Bearer / OAuth | `Authorization: Bearer <token>` |
| Generic API key | `X-API-Key: <key>` |
| Splunk HEC | `Authorization: Splunk <token>` |
| Datadog Logs | `DD-API-KEY: <key>` |
| Wazuh API | `Authorization: Bearer <jwt>` |

Giá trị header được truyền cho curl qua một curl `-K` config file backed bởi memfd, nên secret không bao giờ xuất hiện trong `argv`, `/proc/<pid>/cmdline`, hay bất kỳ danh sách tiến trình nào. Chỉ hỗ trợ một header; các giá trị chứa `\r`, `\n`, `"` hoặc `\` đều bị từ chối khi load config.

**Mutual TLS (tùy chọn, nâng cao):**

Đối với các môi trường đã có PKI (internal CA, cert-manager, SPIFFE, service-mesh issuance), pamsignal có thể xác thực với receiver bằng client certificate. Mạnh hơn xác thực bằng shared-secret: private key không bao giờ truyền qua mạng, và việc xoay vòng thông tin xác thực được giao cho pipeline cert-management.

```ini
webhook_url = https://siem.internal.example.com/ingest
webhook_client_cert = /etc/pamsignal/webhook-client.crt
webhook_client_key  = /etc/pamsignal/webhook-client.key
# Optional: only if the receiver's CA isn't in the system trust store
webhook_ca_bundle   = /etc/pamsignal/webhook-ca.pem
```

mTLS kết hợp cộng thêm với `webhook_auth_header` — các operator có receiver như Wazuh API hay SIEM gateway doanh nghiệp thường yêu cầu cả hai (mTLS cho xác thực danh tính service ở tầng transport, Bearer cho rate-limit / multi-tenancy ở tầng ứng dụng).

**Yêu cầu vận hành:**

- `webhook_client_cert` và `webhook_client_key` phải được đặt cùng nhau; đặt một cái mà không có cái kia là lỗi load config.
- `webhook_client_key` không được phép đọc bởi group hoặc other. Layout khuyến nghị: `0640 root:pamsignal` (hoặc `0600 pamsignal:pamsignal` nếu daemon chạy unprivileged), tương tự như bảo vệ trên chính `pamsignal.conf`.
- Cả ba đường dẫn đều được mở với `O_NOFOLLOW` (symlink bị từ chối) và phải là file thường thuộc sở hữu của `root` hoặc daemon user.
- Các giá trị đường dẫn chứa `\r`, `\n`, `"` hoặc `\` đều bị từ chối khi load config.
- Khóa mã hóa (protected bằng passphrase) không được hỗ trợ. Hãy dùng quyền filesystem, `systemd-creds`, hoặc mô hình secret injection của cert manager.
- Đường dẫn cert/key được đưa qua cùng curl config backed bởi memfd như auth header, nên chúng cũng không xuất hiện trong `argv` — giữ cho process listing của alert child ở mức tối thiểu.

### Các loại sự kiện

| `event.action` (ECS) | `pamsignal.event_type` (legacy) | Khi nào | Severity | Token `enable_notification_type` |
|---|---|---|---|---|
| `session_opened` | `SESSION_OPEN` | PAM session mở ra (sshd / sudo / su / login) | 3 (info) | `session_open` |
| `session_closed` | `SESSION_CLOSE` | PAM session đóng lại | 3 (info) | `session_close` |
| `login_success` | `LOGIN_SUCCESS` | Xác thực SSH thành công (mật khẩu hoặc public key) | 4 (notice) | `login_success` |
| `login_failure` | `LOGIN_FAILED` | Xác thực SSH thất bại | 5 (warning) | `login_failed` |
| `login_failure` (sudo/su) | `LOGIN_FAILED` | Thao tác sudo/su thất bại — **chỉ ghi journal** (không gửi cảnh báo chat theo từng sự kiện; được tính vào ngưỡng brute-force) | 5 (warning) | `login_failed` (chặn lọc riêng vẫn được áp dụng) |
| `brute_force_detected` | `BRUTE_FORCE_DETECTED` | Số lần thất bại từ một IP **hoặc** từ một actor nội bộ (sudo/su) vượt ngưỡng trong cửa sổ thời gian | 8 (alert) | `brute_force` |

Cột cuối cùng là token cần liệt kê trong `enable_notification_type` để nhận loại sự kiện đó dưới dạng cảnh báo chat. Mặc định (`all`, hoặc bỏ qua key) bật mọi loại. Bộ lọc chỉ kiểm soát việc gửi chat — `journalctl -t pamsignal` ghi lại mọi sự kiện bất kể cài đặt. Xem [Configuration → Bộ lọc loại thông báo](./configuration.md#bộ-lọc-loại-thông-báo) để biết tham chiếu đầy đủ.

### Tham chiếu trường (ECS webhook JSON)

| Đường dẫn | Kiểu | Có mặt trong | Mô tả |
|---|---|---|---|
| `@timestamp` | string | Tất cả | ISO 8601 với timezone offset |
| `event.action` | string | Tất cả | Một trong các giá trị trong bảng trên |
| `event.category` | array&lt;string&gt; | Tất cả | Luôn có `"authentication"`; session thêm `"session"`, brute-force thêm `"intrusion_detection"` |
| `event.kind` | string | Tất cả | `"event"` cho quan sát, `"alert"` cho brute-force |
| `event.outcome` | string | Tất cả | `"success"`, `"failure"` hoặc `"unknown"` |
| `event.severity` | integer | Tất cả | 3=info, 4=notice, 5=warning, 8=alert |
| `event.module` | string | Tất cả | Luôn là `"pamsignal"` |
| `event.dataset` | string | Tất cả | Luôn là `"pamsignal.events"` |
| `host.hostname` | string | Tất cả | Hostname của server |
| `user.name` | string | Tất cả | Tên người dùng từ thông điệp PAM |
| `service.name` | string | Login/Session | PAM service: `sshd`, `sudo`, `su`, `login`, `other` |
| `source.ip` | string | Login + Brute | Remote IP (được xác thực qua `inet_pton`) |
| `source.port` | integer | Login | Remote port |
| `process.pid` | integer | Tất cả | Process ID — sshd session đang chạy cho `login_success`/`session_opened`, auth child (đã kết thúc) cho các trường hợp thất bại và brute-force |
| `process.user.id` | string | Login/Session | UID của tiến trình được PAM xử lý |
| `pamsignal.event_type` | string | Tất cả | Legacy uppercase enum (giữ để tương thích ngược cho đến v0.2.x; bỏ trong v0.3.0) |
| `pamsignal.auth_method` | string | Login | `password`, `publickey` hoặc `unknown` |
| `pamsignal.attempts` | integer | Brute-force | Số lần thất bại đã vượt ngưỡng |
| `pamsignal.window_sec` | integer | Brute-force | Cửa sổ thời gian đã cấu hình |

### Tương thích SIEM

ECS payload có thể dùng ngay với:

- **Elastic SIEM** — schema là native; không cần remapping
- **Wazuh** — template wazuh-indexer nhận trực tiếp các sự kiện dạng ECS
- **Sumo Logic, Datadog, Graylog, Loki** — schema linh hoạt; index bất kỳ JSON nào bạn gửi

Cần một bước mapping một lần (Vector / Logstash / Filebeat processor, hoặc pipeline riêng của SIEM) cho:

- **Splunk** — cài [Add-on for Elastic Common Schema] để ánh xạ ECS sang Splunk CIM, hoặc POST lên HEC và viết một Splunk macro tuân theo CIM
- **Microsoft Sentinel** — viết một [KQL parse function](https://learn.microsoft.com/azure/sentinel/normalization-about-parsers) dịch ECS sang ASIM
- **AWS Security Hub** — dịch sang [ASFF] trước khi chuyển tiếp

Đối với các SIEM doanh nghiệp cũ ưa dùng CEF (ArcSight) hoặc LEEF (IBM QRadar), dùng Vector hoặc Logstash để remap các trường ECS. (Chế độ output CEF native nằm trong roadmap nếu có đủ nhu cầu.)

[Add-on for Elastic Common Schema]: https://splunkbase.splunk.com/app/4848
[ASFF]: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html

### Kiến trúc production

Hầu hết SIEM production không nhận webhook trực tiếp. Luồng thông thường là:

```
pamsignal --HTTP--> ingest layer (Vector / Fluent Bit / Logstash) --> SIEM
```

Ví dụ cấu hình Vector nhận từ pamsignal và chuyển tiếp đến Elastic:

```toml
[sources.pamsignal]
type = "http_server"
address = "0.0.0.0:8080"
encoding = "json"

[sinks.elastic]
type = "elasticsearch"
inputs = ["pamsignal"]
endpoints = ["https://es.example.com:9200"]
api_version = "v8"
```

Cùng pattern này áp dụng cho bất kỳ SIEM nào không dùng ECS — thêm bước `transforms.remap` giữa source và sink để đổi tên trường.

## Cơ chế cách ly cảnh báo hoạt động như thế nào

Xem [Architecture — Alert isolation model](./architecture.md#mô-hình-cô-lập-cảnh-báo) để có giải thích đầy đủ. Tóm tắt:

1. Sự kiện **luôn được ghi vào journal trước** (bản ghi cốt lõi được lưu trữ)
2. Tiến trình cha `fork()` một tiến trình con
3. Tiến trình con `exec("curl", ...)` gửi HTTP request
4. Tiến trình cha tiếp tục event loop ngay lập tức — không chờ đợi
5. Nếu tiến trình con bị crash hoặc mạng bị ngắt — tiến trình cha không bị ảnh hưởng
6. Không có HTTP library nào tồn tại trong tiến trình cha
