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

# Login-after-failures detection (0 = disabled)
success_after_fail_threshold = 3

# Trusted sources (default: empty)
trusted_sources = 10.0.0.0/8, 203.0.113.7

# Chat-dispatch filter (default: all)
enable_notification_type = all

# Chat message layout: compact (default) or pretty
message_style = compact

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

## Phát hiện đăng nhập thành công sau nhiều lần thất bại

| Key | Mặc định | Khoảng giá trị | Mô tả |
|-----|---------|-------|-------------|
| `success_after_fail_threshold` | `3` | 0 - 10000 | Số lần thất bại từ một IP khiến lần đăng nhập thành công ngay sau đó trở nên đáng ngờ (0 = tắt) |

Một lần đăng nhập thành công từ một IP vừa thất bại nhiều lần liên tiếp chính là dấu hiệu của một mật khẩu đã bị đoán trúng, và đây là cảnh báo bạn không bao giờ nên bỏ qua. Khi một lần đăng nhập thành công đến từ source IP có ít nhất `success_after_fail_threshold` lần thất bại, lần gần nhất nằm trong `fail_window_sec`, PAMSignal phát cảnh báo `[CRIT]` `login_after_failures` (severity 9), bên cạnh sự kiện `login_success` thông thường.

- **Mỗi sự cố một cảnh báo.** Bất kỳ lần đăng nhập thành công nào từ IP đó đều xoá chuỗi thất bại của nó, nên cảnh báo không lặp lại ở lần đăng nhập kế tiếp.
- **Không bị `trusted_sources` tắt tiếng.** Cảnh báo vẫn bắn với cả các dải tin cậy. Các cảnh báo chat lặp lại cho cùng một IP được giãn cách theo `alert_cooldown_sec`, giống cảnh báo brute-force; journal vẫn ghi lại mọi lần xảy ra. Muốn tắt, hãy đặt ngưỡng về `0` hoặc bỏ `login_after_failures` khỏi `enable_notification_type`.
- **Độc lập với bộ đếm brute-force.** Chuỗi thất bại vẫn được giữ sau khi cảnh báo brute-force đã bắn, nên kẻ tấn công vượt `fail_threshold` rồi mới vào được vẫn bị gắn cờ.
- **Chỉ áp dụng cho đăng nhập từ xa.** Cơ chế này đánh key theo source IP; việc leo quyền nội bộ qua `sudo`/`su` không có IP nên không được bao phủ.

Một người gõ sai mật khẩu của chính mình ba lần rồi mới gõ đúng cũng sẽ kích hoạt cảnh báo này. Hãy nâng ngưỡng lên nếu chuyện đó thường xảy ra trên host của bạn.

## Nguồn tin cậy

| Key | Mặc định | Mô tả |
|-----|---------|-------------|
| `trusted_sources` | *(rỗng)* | Danh sách địa chỉ IPv4/IPv6 hoặc dải CIDR phân cách bằng dấu phẩy (tối đa 32) mà cảnh báo đăng nhập thông thường từ đó sẽ không được gửi lên chat |

Dùng key này cho những nơi bạn đăng nhập hằng ngày — dải IP văn phòng, VPN, bastion host — để các lần đăng nhập đó thôi ping vào kênh.

```ini
trusted_sources = 10.0.0.0/8, 203.0.113.7, 2001:db8::/32
```

- **Cái gì bị tắt tiếng.** Chỉ các cảnh báo chat theo từng sự kiện `login_success` và `login_failed` của những sự kiện có source IP nằm trong một dải đã liệt kê.
- **Cái gì vẫn bắn.** Cảnh báo `brute_force` và `login_after_failures`. Một máy bị chiếm quyền nằm trong dải tin cậy không thể tấn công trong im lặng.
- **Journal không bị ảnh hưởng.** `journalctl -t pamsignal` vẫn ghi lại mọi sự kiện từ mọi nguồn.
- **Sự kiện session không được bao phủ.** `session_open` / `session_close` không mang source IP. Hãy tắt chúng bằng `enable_notification_type`.

Một địa chỉ đứng riêng nghĩa là đúng một host đó. Độ dài prefix phải ít nhất là 1 (`0.0.0.0/0` bị từ chối), hostname không được resolve, và một phần tử sai định dạng là lỗi config cứng. Một peer IPv6 dạng IPv4-mapped (`::ffff:10.1.2.3`) được so khớp với các phần tử IPv4.

## Bộ lọc loại thông báo

`enable_notification_type` cho phép chọn những loại sự kiện nào sẽ kích hoạt cảnh báo trên các kênh chat. Đây là danh sách phân cách bằng dấu phẩy. Mặc định — khi key bị bỏ qua hoặc khi `all` được chỉ định — là mọi loại sự kiện, giữ nguyên hành vi trước đó. Các token không hợp lệ là lỗi config cứng; giá trị rỗng và các phần tử danh sách rỗng đều bị từ chối.

| Token | Kích hoạt cảnh báo chat khi… |
|-------|---------------------------|
| `login_success` | Phát hiện đăng nhập thành công (sshd, login) |
| `login_failed` | Phát hiện đăng nhập thất bại (sshd, login; lỗi sudo/su vẫn chịu sự chặn lọc riêng theo từng sự kiện — xem bên dưới) |
| `session_open` | Một PAM session mở ra (bao gồm cả các session nền của systemd như cron) |
| `session_close` | Một PAM session đóng lại |
| `brute_force` | Ngưỡng brute-force từ xa (theo IP) hoặc nội bộ (theo actor sudo/su) bị vượt qua |
| `login_after_failures` | Một lần đăng nhập thành công đến từ IP vừa có chuỗi thất bại gần đây (xem [Phát hiện đăng nhập thành công sau nhiều lần thất bại](#phát-hiện-đăng-nhập-thành-công-sau-nhiều-lần-thất-bại)) |
| `all` | Sentinel cho tất cả các loại ở trên (tương đương với việc bỏ qua key) |

> **Nâng cấp khi đang dùng danh sách tường minh?** `login_after_failures` là một loại mới. Nếu config của bạn đã liệt kê các token cụ thể (ví dụ `login_success,brute_force`), hãy thêm `login_after_failures` để tiếp tục nhận cảnh báo này trên chat; với `all` hoặc khi bỏ qua key, bạn sẽ tự động nhận được.

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

## Kiểu hiển thị tin nhắn

| Key | Mặc định | Giá trị | Mô tả |
|-----|---------|--------|-------------|
| `message_style` | `compact` | `compact`, `pretty` | Cách trình bày cảnh báo gửi tới các kênh chat |

`compact` là dòng văn bản `key=value` mà PAMSignal vẫn gửi từ trước đến nay. `pretty` dễ đọc hơn trên điện thoại: một dòng tiêu đề, rồi mỗi trường một dòng với nhãn in đậm và giá trị dạng monospace.

```ini
message_style = pretty
```

```text
🚨 Brute force detected
Host: web-01
Source: 203.0.113.50
User: root
Attempts: 12 in 300s
Time: 2026-03-29 14:23:01 +0000
```

- **Markup theo từng nền tảng.** Mỗi kênh nhận đúng cú pháp của nó (Telegram HTML, Slack mrkdwn, markdown của Teams và Discord, định dạng của WhatsApp), nên nhãn luôn hiển thị đậm và giá trị luôn ở dạng monospace. Xem [Alerts → Định dạng pretty](./alerts.md#định-dạng-pretty).
- **An toàn với dữ liệu thù địch.** Tên user và tên host đến từ journal và có thể bị kẻ tấn công chi phối. Ở cả hai kiểu, chúng chỉ được gửi bên trong một code span, sau khi backtick, ký tự markup, ký tự điều khiển và Unicode vô hình đã bị vô hiệu hoá, nên một lần thử đăng nhập với tên `<!channel>`, `@everyone` hay `[click](https://evil.example)` không thể ping ai hay trở thành link. Xem [Alerts → Cách vô hiệu hoá văn bản không đáng tin](./alerts.md#cách-vô-hiệu-hoá-văn-bản-không-đáng-tin).
- **Tự lùi về compact khi quá dài.** Một tin nhắn pretty không vừa giới hạn sẽ được gửi ở dạng compact thay vì bị cắt cụt.
- **Compact hiển thị monospace.** Bản thân dòng compact cũng được gửi như một code span, nên nó hiển thị bằng font độ rộng cố định trên mọi nền tảng.
- **Webhook không bị ảnh hưởng.** ECS JSON của custom webhook giống hệt nhau ở cả hai kiểu.

Chạy `sudo -u pamsignal pamsignal --test-alert` để xem kiểu đã chọn ngay trong kênh của bạn trước khi reload.

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
| `--check-config` | `-t` | Kiểm tra file config, in ra các lỗi (nếu có) rồi thoát |
| `--test-alert` | `-T` | Gửi một tin nhắn thử tới mọi kênh đã cấu hình rồi thoát |

Đường dẫn tương đối sẽ được chuyển thành đường dẫn tuyệt đối trước khi daemonize. Một option không được nhận diện, hoặc `-c` thiếu đường dẫn, là lỗi: pamsignal in ra thông báo và thoát với mã `2` thay vì khởi động.

## Kiểm tra config và thử cảnh báo

Sau khi sửa config, hãy kiểm tra nó trước khi reload, rồi xác nhận các kênh thực sự gửi được:

```bash
sudo -u pamsignal pamsignal --check-config
sudo -u pamsignal pamsignal --test-alert
```

`--check-config` in ra từng lỗi kèm số dòng và thoát với mã `1`, hoặc in một bản tóm tắt ngắn và thoát với mã `0`:

```text
pamsignal: config:2: trusted_sources must be a comma-separated list of at most 32 IPv4/IPv6 addresses or CIDR networks (prefix length 1 or more)
pamsignal: config has 1 error(s)
```

```text
pamsignal: /etc/pamsignal/pamsignal.conf: configuration OK
  alert channels: telegram slack
  trusted sources: 2
```

`--test-alert` gửi một tin nhắn thử cho mỗi kênh đã cấu hình, chờ từng kênh hoàn tất, rồi in ra kết quả. Một request bị từ chối (sai token, webhook đã bị thu hồi) được tính là thất bại, và lỗi của chính curl được hiển thị ngay phía trên dòng kết quả:

```text
telegram  ok
curl: (22) The requested URL returned error: 404
slack     FAILED (curl exit code 22; see the curl message above)
pamsignal: 1 alert channel(s) failed
```

Lệnh chỉ thoát với mã `0` khi mọi kênh đã cấu hình đều nhận tin nhắn. Tin nhắn thử bỏ qua `enable_notification_type` và `alert_cooldown_sec`.

Cả hai lệnh phải chạy bằng service user, không phải root: các kiểm tra ownership trên file config và file TLS key được tính theo user đang chạy lệnh, nên chỉ khi đó kết quả mới khớp với những gì daemon sẽ thấy. Cả hai đều dùng được với `-c PATH`.

## Reload không cần restart

```bash
sudo systemctl reload pamsignal
```

Lệnh này gửi SIGHUP đến daemon. Nếu config mới hợp lệ, nó có hiệu lực ngay lập tức và bảng theo dõi brute-force sẽ được reset. Nếu config có lỗi, daemon giữ nguyên config hiện tại và ghi log cảnh báo.
