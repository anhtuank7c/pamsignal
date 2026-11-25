# Alerts

> [English](../alerts.md) · **Tiếng Việt**

PAMSignal gửi cảnh báo best-effort đến các nền tảng nhắn tin khi phát hiện sự kiện đăng nhập hoặc pattern brute-force. Cảnh báo được gửi qua `fork()+exec(curl)`, một tiến trình con tồn tại trong thời gian ngắn, không thể ảnh hưởng đến quá trình giám sát cốt lõi.

Nếu một cảnh báo thất bại (mạng bị ngắt, lỗi API, timeout), daemon vẫn chạy tiếp mà không hề biết: nó không bao giờ chờ tiến trình con curl hay đọc kết quả của nó. pamsignal chỉ ghi warning vào journal khi không thể dựng hoặc khởi chạy cảnh báo (tin nhắn quá dài, `memfd_create()` hoặc `fork()` thất bại). Hãy chạy `pamsignal --test-alert` để kiểm tra từng kênh từ đầu đến cuối. Sự kiện luôn được ghi vào journal trước tiên.

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

- **Các kênh chat** (Telegram / Slack / Teams / WhatsApp / Discord) nhận tin nhắn văn bản một dòng, có tiền tố severity dạng `key=value` (`message_style = compact`, mặc định) hoặc tin nhắn nhiều dòng (`message_style = pretty`, xem [Định dạng pretty](#định-dạng-pretty)).
- **Custom webhook** nhận một JSON document với các object ECS lồng nhau (`event.*`, `host.*`, `user.*`, `source.*`, `service.*`, `process.*`) cộng với namespace `pamsignal.*` cho các trường riêng của vendor.

Điều này có nghĩa là output của webhook có thể đưa thẳng vào Elastic SIEM và Wazuh mà không cần remapping, và chỉ cần một config Vector / Logstash để kết nối với bất kỳ SIEM hiện đại nào khác.

[Elastic Common Schema (ECS)]: https://www.elastic.co/guide/en/ecs/current/index.html

### Định dạng văn bản chat

Dấu ngoặc severity có độ rộng cố định (8 ký tự) để các cột thẳng hàng khi hiển thị monospace. Thứ tự trường là severity → action → identity → location → metadata → `pid` → `ts`. Trường `pid=` là tiến trình đang chạy cho các sự kiện `session_opened` và `login_success` (bạn có thể `kill <pid>` để ngắt kết nối người dùng) và là auth child đã kết thúc cho các trường hợp thất bại (đã được thu hồi, nên chỉ hữu ích như thông tin forensics). Với `session_opened`, `actor=` là tài khoản đã đăng nhập vào phiên mà từ đó `sudo`/`su` được chạy (phần `by <name>(uid=N)` trong log của pam_unix). Thường đó chính là người đã chạy lệnh, nhưng nếu alice chạy `su - bob` rồi bob mới chạy `sudo`, actor vẫn là `alice`; log của chính sudo mới ghi tài khoản đã gõ `sudo`. `actor=` bị bỏ qua khi nó chỉ lặp lại `user=` (một lần đăng nhập SSH được ghi là `alice(uid=1001) by alice(uid=0)`), với đăng nhập console (`by LOGIN(uid=0)`, trong đó `LOGIN` chỉ là chuỗi giữ chỗ) và khi pam_unix không ghi tên (`by (uid=0)`, sudo chạy ngoài phiên đăng nhập, ví dụ từ cron).

```
[INFO]   auth.session_opened user=root actor=alice host=web-01 service=sudo pid=12345 ts=2026-03-29T14:23:01+0000 provider=aws service_name=web-api
[INFO]   auth.session_closed user=root host=web-01 service=sshd pid=12346 ts=2026-03-29T14:25:10+0000 provider=aws service_name=web-api
[NOTICE] auth.login_success user=admin src=192.168.1.100:52341 host=web-01 service=sshd auth=password pid=12345 ts=2026-03-29T14:23:01+0000
[WARN]   auth.login_failure user=root src=203.0.113.50:39182 host=web-01 service=sshd auth=password pid=12347 ts=2026-03-29T14:23:01+0000
[ALERT]  auth.brute_force_detected src=203.0.113.50 attempts=12 window=300s user=root host=web-01 pid=12347 ts=2026-03-29T14:23:01+0000
[ALERT]  auth.brute_force_detected actor=alice target=root attempts=5 window=300s service=sudo host=web-01 pid=12348 ts=2026-03-29T14:23:01+0000
[CRIT]   auth.login_after_failures user=root src=203.0.113.50:40112 failures=7 window=300s host=web-01 service=sshd auth=password pid=12360 ts=2026-03-29T14:24:10+0000
```

Dòng brute-force có `actor=` / `target=` được phát ra khi một user nội bộ (`alice`) liên tục thất bại khi xác thực qua `sudo`/`su` trên host. Không có `src=` vì thao tác không có remote endpoint; ECS `user.name` mang tên actor và `user.target.name` là mục tiêu leo thang quyền. Cảnh báo `auth.login_failure` theo từng sự kiện **không** được phát cho sudo/su. Chỉ có cảnh báo brute-force tổng hợp mới được gửi, để một lần gõ sai mật khẩu không làm phiền operator. Tuy nhiên, bản ghi journal từ `pamsignal` vẫn được ghi cho mỗi lần thất bại riêng lẻ.

Dòng `[CRIT]` là cảnh báo login-after-failures: một lần đăng nhập đã **thành công** từ một IP vừa thất bại `failures` lần, đúng với hình ảnh của một mật khẩu bị đoán trúng. Cảnh báo này được gửi thêm bên cạnh dòng `auth.login_success` thông thường, và vẫn bắn kể cả với `trusted_sources`; các lần lặp lại cho cùng một IP được giãn cách theo `alert_cooldown_sec`. Xem [Configuration → Phát hiện đăng nhập thành công sau nhiều lần thất bại](./configuration.md#phát-hiện-đăng-nhập-thành-công-sau-nhiều-lần-thất-bại).

*(Lưu ý: Các tag context tùy chỉnh như `provider=aws service_name=web-api` sẽ tự động được thêm vào nếu được cấu hình trong `pamsignal.conf`)*

### Định dạng pretty

Đặt `message_style = pretty` để thay dòng đơn ở trên bằng một tin nhắn nhiều dòng: một dòng tiêu đề, rồi mỗi trường một dòng với nhãn in đậm và giá trị dạng monospace. Dòng tiêu đề thay cho nhãn severity và tên action, còn các dòng của từng sự kiện được liệt kê trong bảng bên dưới. Những gì từng nền tảng nhận được:

```text
Telegram (HTML parse mode)
🚨 <b>Brute force detected</b>
<b>Host:</b> <code>web-01</code>
<b>Source:</b> <code>203.0.113.50</code>
<b>User:</b> <code>root</code>
<b>Attempts:</b> <code>12 in 300s</code>
<b>Time:</b> <code>2026-03-29 14:23:01 +0000</code>

Slack / WhatsApp
🚨 *Brute force detected*
*Host:* `web-01`
*Source:* `203.0.113.50`

Discord
🚨 **Brute force detected**
**Host:** `web-01`
**Source:** `203.0.113.50`
```

| Tiêu đề | Sự kiện | Các dòng |
|---|---|---|
| ✅ Login success / ❌ Login failed | `login_success`, `login_failure` | Host, User, Source (chỉ với đăng nhập từ xa), Auth, PID, Time |
| 🔓 Session opened / 🔒 Session closed | `session_opened`, `session_closed` (sshd và các service khác) | Host, User, Actor (nếu có), Service, PID, Time |
| 🔓 Console login / 🔒 Console logout | `session_opened`, `session_closed` (`login`) | Host, User, Service, PID, Time |
| 🔑 Sudo to root (hoặc Sudo used) / 🔒 Sudo ended | `session_opened`, `session_closed` (`sudo`) | Host, By (nếu có), Run as, PID, Time |
| 🔁 Switched to root (hoặc User switched) / 🔒 User switch ended | `session_opened`, `session_closed` (`su`) | Host, From (nếu có), Switched to, PID, Time |
| 🚨 Brute force detected | `brute_force_detected` (từ xa) | Host, Source, User, Attempts, Time |
| 🚨 Brute force detected (local) | `brute_force_detected` (sudo/su) | Host, Actor, Target, Service, Attempts, Time |
| 🔥 Login after failed attempts | `login_after_failures` | Host, User, Source, Failures, Auth, PID, Time |
| 🔔 PAMSignal test alert | `pamsignal --test-alert` | Host, Time |

Một session `sudo` hoặc `su` không phải là một lần đăng nhập: đó là một người đã ở trên máy đang hành động dưới danh nghĩa một tài khoản khác, nên tiêu đề nói đúng điều đó thay vì "Session opened". "Sudo to root" và "Switched to root" được dùng khi tài khoản đích là `root`, "Sudo used" và "User switched" cho mọi tài khoản khác. **By** / **From** là actor (xem phần giải thích `actor=` phía trên), còn **Run as** / **Switched to** là user của session. Alert đóng của một lệnh `sudo <lệnh>` thông thường đến ngay sau khi lệnh chạy xong; với `su -`, `sudo -i` hoặc `sudo su` nó đánh dấu thời điểm người dùng rời khỏi shell root. Chỉ kiểu pretty thay đổi: dòng compact, tên sự kiện và JSON của webhook giữ nguyên cho mọi service.

Các dòng `Provider` và `Service name` được thêm vào khi các tag đó được cấu hình. Teams nhận đúng các dòng đó trong một Adaptive Card: tiêu đề và nhãn in đậm, giá trị dạng monospace (xem [Microsoft Teams](#microsoft-teams)).

### Cách vô hiệu hoá văn bản không đáng tin

Tên user và tên host đến từ journal, và tên user do chính người đang cố đăng nhập chọn. Không có gì bắt nguồn từ chúng được gửi đi như văn bản tin nhắn thông thường, ở cả hai kiểu:

- **Pretty:** mọi giá trị là nội dung của một code span.
- **Compact:** cả dòng được gửi như một code span duy nhất (`<code>…</code>` trên Telegram, backtick ở các nền tảng khác), nên nó cũng hiển thị dạng monospace, đúng với cách bố cục độ rộng cố định của nó được thiết kế.
- **Teams:** markdown của Adaptive Card không có code span, nên mọi đoạn văn bản là một `TextRun` bên trong một `RichTextBlock`, thứ mà Teams không bao giờ phân tích như markdown. Các dòng về ký tự điều khiển và Unicode trong bảng dưới vẫn áp dụng; dòng về backtick và `&` `<` `>` thì không, vì ở đó các ký tự này vô hại.

Bên trong một code span, không nền tảng nào phân tích markup, resolve mention hay biến văn bản thành link. Trước khi văn bản được đưa vào:

| Đầu vào | Trở thành | Lý do |
|---|---|---|
| Dấu backtick | `'` | Đây là ký tự duy nhất có thể đóng một code span |
| `&` `<` `>` | `&amp;` `&lt;` `&gt;` trên Telegram, Slack | Ở đó chúng là cú pháp (HTML tag, `<!channel>`, `<url\|text>`) |
| Ký tự điều khiển, gồm cả CR / LF / TAB | `?` | Một dấu xuống dòng sẽ mở ra một dòng giả mạo |
| Ký tự phân tách dòng và đoạn của Unicode (U+2028, U+2029), C1 control | `?` | Tương tự, với các client coi chúng là dấu xuống dòng |
| Bidirectional override và isolate (U+202A–202E, U+2066–2069), ký tự zero-width và các ký tự định dạng vô hình khác | `?` | Chúng đảo thứ tự hoặc che giấu văn bản hiển thị |
| Byte không phải UTF-8 hợp lệ | `?` | Nếu không, API chat sẽ từ chối cả request, khiến cảnh báo bị chặn |

Vì vậy một lần thử đăng nhập với tên `[reset-password](https://evil.example)`, `https://evil.example`, `@everyone`, `<!channel>` hay `/start` sẽ đến nơi đúng như chuỗi văn bản đó và không gì hơn. Cảnh báo gửi tới Discord còn kèm `"allowed_mentions":{"parse":[]}`. Một tin nhắn vượt quá 2000 byte sẽ được gửi ở dạng compact, và nếu vẫn không vừa thì cảnh báo bị bỏ kèm một dòng warning trong journal thay vì bị cắt giữa chừng markup.

Kiểm tra UTF-8 này cũng áp dụng cho JSON của custom webhook: một byte không hợp lệ trong một trường sẽ thành `?` để body luôn parse được.

### Telegram

Gửi qua [Bot API `sendMessage`](https://core.telegram.org/bots/api#sendmessage) với `parse_mode` là `HTML` ở cả hai kiểu: dòng compact được bọc trong `<code>`, tin nhắn pretty dùng `<b>` và `<code>`.

**Cài đặt:**
1. Tạo bot với [@BotFather](https://t.me/BotFather) và sao chép token
2. Thêm bot vào group/channel của bạn
3. Lấy chat ID (gửi một tin nhắn, sau đó kiểm tra `https://api.telegram.org/bot<token>/getUpdates`)
4. Đặt `telegram_bot_token` và `telegram_chat_id` trong `pamsignal.conf`. Token phải có dạng `<chữ số>:<ít nhất 20 ký tự A-Z a-z 0-9 _ ->`; chat ID là một số (âm với group) hoặc `@channelusername`. Cả hai đều được kiểm tra khi load config.

### Slack

Gửi trong trường `text` qua [incoming webhook](https://api.slack.com/messaging/webhooks): dòng compact bọc trong backtick, hoặc tin nhắn pretty theo Slack mrkdwn.

**Cài đặt:**
1. Vào [Slack App Directory](https://api.slack.com/apps) và tạo một app
2. Bật **Incoming Webhooks** và tạo webhook cho channel của bạn
3. Đặt `slack_webhook_url` trong `pamsignal.conf`

### Microsoft Teams

Gửi dưới dạng một [Adaptive Card](https://adaptivecards.io/) tới webhook **Workflows** của Teams. Microsoft đã ngừng hỗ trợ các webhook Office 365 connector (`https://<tenant>.webhook.office.com/...`), nên URL connector không còn gửi được gì; hãy tạo một webhook Workflows thay thế.

> **Chưa được kiểm thử trên một Teams tenant thật.** Định dạng card đã có unit test, nhưng chưa có alert nào được gửi tới một webhook Workflows thật. Nếu bạn chạy thử, hãy báo kết quả (chạy được, hoặc lỗi mà Teams trả về) trong một issue.

Với `message_style = pretty`, card chứa tin nhắn pretty (tiêu đề và nhãn in đậm, giá trị dạng monospace); nếu không, card chứa dòng compact bằng font monospace. Request body cho một alert compact:

```json
{
  "type": "message",
  "attachments": [{
    "contentType": "application/vnd.microsoft.card.adaptive",
    "contentUrl": null,
    "content": {
      "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
      "type": "AdaptiveCard",
      "version": "1.2",
      "body": [
        {"type": "RichTextBlock", "inlines": [
          {"type": "TextRun", "text": "[WARN]   auth.login_failure user=bob src=192.0.2.1:22 ...", "fontType": "Monospace"}
        ]}
      ]
    }
  }]
}
```

**Cài đặt:**
1. Trong Teams, mở menu **...** cạnh channel và chọn **Workflows**
2. Chọn template **Send webhook alerts to a channel**, đặt tên cho workflow, rồi xác nhận team và channel
3. Sao chép webhook URL được hiển thị và đặt nó làm `teams_webhook_url` trong `pamsignal.conf`
4. Chạy `sudo -u pamsignal pamsignal --test-alert`

Card được đăng bởi tài khoản đã tạo workflow (hiển thị là "<name> via Workflows"). Hãy giữ bí mật URL này: ai có nó đều có thể đăng vào channel. URL dài tối đa 511 ký tự.

### WhatsApp

Gửi dưới dạng tin nhắn `text` qua [Meta WhatsApp Cloud API](https://developers.facebook.com/docs/whatsapp/cloud-api) (`POST https://graph.facebook.com/v21.0/<phone_number_id>/messages`, token được gửi dưới dạng Bearer header).

**Cài đặt:**
1. Tạo [Meta Business app](https://developers.facebook.com/apps/) và thêm WhatsApp
2. Lấy **Phone Number ID** và tạo **permanent access token**
3. Đặt `whatsapp_access_token`, `whatsapp_phone_number_id` và `whatsapp_recipient` trong `pamsignal.conf`. Phone number ID và recipient chỉ được chứa chữ số (định dạng quốc tế, không có `+`).

> **Lưu ý:** WhatsApp Cloud API yêu cầu tài khoản Meta Business đã xác minh cho mục đích sử dụng thực tế (production).

### Discord

Gửi trong trường `content` qua [Discord webhook](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks), kèm `allowed_mentions` để không mention nào được resolve.

**Cài đặt:**
1. Trong Discord channel của bạn, vào **Settings > Integrations > Webhooks > New Webhook**
2. Đặt `discord_webhook_url` trong `pamsignal.conf`

### Custom webhook (ECS JSON)

Gửi dưới dạng request `POST` với `Content-Type: application/json`. Tuân theo ECS nên có thể đưa vào Elastic Stack, Wazuh, hoặc bất kỳ pipeline nào hỗ trợ ECS mà không cần remapping trường.

> **Muốn xây dựng receiver của riêng bạn?** Xem các receiver sẵn sàng triển khai bằng **[Node.js](examples/nodejs-webhook.md)** và **[Python](examples/python-webhook.md)**. Chúng minh họa cách xác thực, phân tích cú pháp ECS JSON payload, và định tuyến các sự kiện PAMSignal.

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

**Sự kiện session** (không có `source.*` vì đây không phải sự kiện mạng). `pamsignal.actor` chỉ có mặt ở `session_opened` khi biết được actor (xem [Định dạng văn bản chat](#định-dạng-văn-bản-chat)):

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
  "pamsignal": {"event_type": "SESSION_OPEN", "actor": "alice"}
}
```

**Phát hiện brute-force, từ xa (sshd, hoặc sudo/su có `rhost=`)**: được đánh key theo source IP, `event.kind=alert`, severity 8:

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

**Phát hiện brute-force, nội bộ (sudo/su không có remote endpoint)**: được đánh key theo actor (`ruser=`), không có `source.*`. `user.name` là actor; `user.target.name` là mục tiêu leo thang quyền:

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

**Đăng nhập sau nhiều lần thất bại**: một lần đăng nhập từ xa thành công ngay sau một chuỗi thất bại, `event.kind=alert`, `event.outcome=success`, severity 9. Không có `process.user.id`:

```json
{
  "@timestamp": "2026-03-29T14:24:10+0000",
  "event": {
    "action": "login_after_failures",
    "category": ["authentication", "intrusion_detection"],
    "kind": "alert",
    "outcome": "success",
    "severity": 9,
    "module": "pamsignal",
    "dataset": "pamsignal.events"
  },
  "host": {"hostname": "web-01"},
  "user": {"name": "root"},
  "service": {"name": "sshd"},
  "source": {"ip": "203.0.113.50", "port": 40112},
  "process": {"pid": 12360},
  "pamsignal": {
    "event_type": "LOGIN_AFTER_FAILURES",
    "auth_method": "password",
    "failures": 7,
    "window_sec": 300
  }
}
```

**Test alert** (chỉ với `pamsignal --test-alert`; không phải một phát hiện):

```json
{
  "@timestamp": "2026-03-29T14:30:00+0000",
  "event": {
    "action": "test_alert",
    "category": ["configuration"],
    "kind": "event",
    "outcome": "success",
    "severity": 3,
    "module": "pamsignal",
    "dataset": "pamsignal.events"
  },
  "host": {"hostname": "web-01"},
  "pamsignal": {"event_type": "TEST_ALERT"}
}
```

Mọi payload đều có cùng object `labels` khi `provider` hoặc `service_name` được đặt.

**Chi tiết HTTP:**

| Thuộc tính | Giá trị |
|----------|-------|
| Method | `POST` |
| Content-Type | `application/json` |
| Scheme | Chỉ HTTPS: `webhook_url` phải bắt đầu bằng `https://`, và curl chạy với `--proto =https --proto-redir =https` |
| Timeout | 10 giây (`--max-time 10`) |
| Response | Không được kiểm tra. Việc gửi là fire-and-forget nên status non-2xx không được ghi log. `pamsignal --test-alert` thì có kiểm tra (curl `-f`) và báo từng kênh là `ok` hoặc `FAILED` |

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

Giá trị header được truyền cho curl qua một curl `-K` config file backed bởi memfd, nên secret không bao giờ xuất hiện trong `argv`, `/proc/<pid>/cmdline`, hay bất kỳ danh sách tiến trình nào. Chỉ hỗ trợ một header. Header phải có dạng `Name: value` và cần có `webhook_url`; giá trị chứa ký tự điều khiển (kể cả `\r` và `\n`), `"` hoặc `\` đều bị từ chối khi load config.

**Mutual TLS (tùy chọn, nâng cao):**

Đối với các môi trường đã có PKI (internal CA, cert-manager, SPIFFE, service-mesh issuance), pamsignal có thể xác thực với receiver bằng client certificate. Mạnh hơn xác thực bằng shared-secret: private key không bao giờ truyền qua mạng, và việc xoay vòng thông tin xác thực được giao cho pipeline cert-management.

```ini
webhook_url = https://siem.internal.example.com/ingest
webhook_client_cert = /etc/pamsignal/webhook-client.crt
webhook_client_key  = /etc/pamsignal/webhook-client.key
# Optional: only if the receiver's CA isn't in the system trust store
webhook_ca_bundle   = /etc/pamsignal/webhook-ca.pem
```

mTLS kết hợp cộng thêm với `webhook_auth_header`. Các operator có receiver như Wazuh API hay SIEM gateway doanh nghiệp thường yêu cầu cả hai (mTLS cho xác thực danh tính service ở tầng transport, Bearer cho rate-limit / multi-tenancy ở tầng ứng dụng).

**Yêu cầu vận hành:**

- `webhook_client_cert` và `webhook_client_key` phải được đặt cùng nhau; đặt một cái mà không có cái kia là lỗi load config.
- Cả ba key đều cần có `webhook_url`.
- `webhook_client_key` không được phép đọc bởi group hoặc other (bất kỳ bit đọc nào của group hoặc other đều là lỗi load config), và curl chạy dưới daemon user, nên key phải thuộc sở hữu của user đó: dùng `0600 pamsignal:pamsignal` (hoặc `0400`). Key `0640 root:pamsignal` sẽ bị từ chối.
- Cả ba đường dẫn đều được mở với `O_NOFOLLOW` (symlink bị từ chối) khi load config và phải tồn tại dưới dạng file thường thuộc sở hữu của `root` hoặc daemon user.
- Các giá trị đường dẫn chứa `\r`, `\n`, `"` hoặc `\` đều bị từ chối khi load config.
- Khóa mã hóa (protected bằng passphrase) không được hỗ trợ. Hãy dùng quyền filesystem, `systemd-creds`, hoặc mô hình secret injection của cert manager.
- Đường dẫn cert/key được đưa qua cùng curl config backed bởi memfd như auth header, nên chúng cũng không xuất hiện trong `argv`, giúp process listing của alert child ở mức tối thiểu.

### Các loại sự kiện

| `event.action` (ECS) | `pamsignal.event_type` | Khi nào | Severity | Token `enable_notification_type` |
|---|---|---|---|---|
| `session_opened` | `SESSION_OPEN` | PAM session mở ra (sshd / sudo / su / login) | 3 (info) | `session_open` |
| `session_closed` | `SESSION_CLOSE` | PAM session đóng lại | 3 (info) | `session_close` |
| `login_success` | `LOGIN_SUCCESS` | Xác thực SSH thành công (mật khẩu, public key hoặc keyboard-interactive) | 4 (notice) | `login_success` |
| `login_failure` | `LOGIN_FAILED` | Xác thực SSH thất bại (mật khẩu hoặc keyboard-interactive), hoặc `login` trên console thất bại | 5 (warning) | `login_failed` |
| `login_failure` (sudo/su) | `LOGIN_FAILED` | Thao tác sudo/su thất bại, **chỉ ghi journal** (không gửi cảnh báo chat theo từng sự kiện; được tính vào ngưỡng brute-force) | 5 (warning) | `login_failed` (chặn lọc riêng vẫn được áp dụng) |
| `brute_force_detected` | `BRUTE_FORCE_DETECTED` | Số lần thất bại từ một IP **hoặc** từ một actor nội bộ (sudo/su) vượt ngưỡng trong cửa sổ thời gian | 8 (alert) | `brute_force` |
| `login_after_failures` | `LOGIN_AFTER_FAILURES` | Một lần đăng nhập thành công từ IP có ít nhất `success_after_fail_threshold` lần thất bại gần đây: nhiều khả năng mật khẩu đã bị đoán trúng | 9 (critical) | `login_after_failures` |

Cột cuối cùng là token cần liệt kê trong `enable_notification_type` để nhận loại sự kiện đó dưới dạng cảnh báo chat. Mặc định (`all`, hoặc bỏ qua key) bật mọi loại. Bộ lọc kiểm soát cả việc gửi chat lẫn custom webhook; `journalctl -t pamsignal` ghi lại mọi sự kiện bất kể cài đặt. Xem [Configuration → Bộ lọc loại thông báo](./configuration.md#bộ-lọc-loại-thông-báo) để biết tham chiếu đầy đủ.

`pamsignal --test-alert` gửi thêm một payload không phải là phát hiện: `event.action` = `test_alert`, `event.category` = `["configuration"]`, `pamsignal.event_type` = `TEST_ALERT`, severity 3, chỉ gồm `@timestamp`, `event.*`, `host.hostname` và `labels` (nếu có) (xem ví dụ ở trên). Receiver có thể bỏ qua hoặc dùng nó để kiểm tra kết nối.

### Tham chiếu trường (ECS webhook JSON)

| Đường dẫn | Kiểu | Có mặt trong | Mô tả |
|---|---|---|---|
| `@timestamp` | string | Tất cả | ISO 8601 với timezone offset |
| `event.action` | string | Tất cả | Một trong các giá trị trong bảng trên, hoặc `test_alert` |
| `event.category` | array&lt;string&gt; | Tất cả | `"authentication"` đứng đầu; session thêm `"session"`, brute-force và login-after-failures thêm `"intrusion_detection"`. Test alert chỉ có `"configuration"` |
| `event.kind` | string | Tất cả | `"event"` cho quan sát và test alert, `"alert"` cho brute-force và login-after-failures |
| `event.outcome` | string | Tất cả | `"success"`, `"failure"` hoặc `"unknown"` (brute-force) |
| `event.severity` | integer | Tất cả | 3=info, 4=notice, 5=warning, 8=alert, 9=critical |
| `event.module` | string | Tất cả | Luôn là `"pamsignal"` |
| `event.dataset` | string | Tất cả | Luôn là `"pamsignal.events"` |
| `host.hostname` | string | Tất cả | Hostname của server |
| `user.name` | string | Tất cả trừ test alert | Tên người dùng từ thông điệp PAM; với brute-force nội bộ là actor |
| `user.target.name` | string | Brute-force nội bộ | Tài khoản mà actor cố leo thang lên |
| `service.name` | string | Login, session, brute-force nội bộ, login-after-failures | PAM service: `sshd`, `sudo`, `su`, `login`, `other` |
| `source.ip` | string | Login + brute-force từ xa + login-after-failures | Remote IP (được xác thực qua `inet_pton`); chuỗi rỗng khi dòng log không có IP (ví dụ `login` nội bộ thất bại) |
| `source.port` | integer | Login + Login-after-failures | Remote port (0 khi không rõ) |
| `process.pid` | integer | Tất cả trừ test alert | Process ID: sshd session đang chạy cho `login_success`/`session_opened`, auth child (đã kết thúc) cho các trường hợp thất bại và brute-force |
| `process.user.id` | string | Login/Session | UID của tiến trình được PAM xử lý |
| `pamsignal.event_type` | string | Tất cả | Tên sự kiện viết hoa (`SESSION_OPEN`, `LOGIN_FAILED`, `BRUTE_FORCE_DETECTED`, `LOGIN_AFTER_FAILURES`, `TEST_ALERT`, ...). Vẫn được gửi trong mọi payload |
| `pamsignal.actor` | string | Session opened (nếu có) | Tài khoản đã đăng nhập vào phiên mà `sudo`/`su` chạy từ đó, thường là người đã chạy lệnh (xem lưu ý về `su` ở phần định dạng văn bản chat phía trên). `user.name` vẫn là user của session. Không có mặt khi trùng với `user.name` (một lần đăng nhập SSH), với đăng nhập console (`LOGIN`), hoặc khi pam_unix không ghi tên |
| `pamsignal.auth_method` | string | Login + Login-after-failures | `password`, `publickey`, `keyboard-interactive` hoặc `unknown` |
| `pamsignal.attempts` | integer | Brute-force | Số lần thất bại đã vượt ngưỡng |
| `pamsignal.failures` | integer | Login-after-failures | Độ dài chuỗi lần thất bại xảy ra ngay trước lần đăng nhập thành công |
| `pamsignal.window_sec` | integer | Brute-force + Login-after-failures | Cửa sổ thời gian đã cấu hình |
| `labels.provider` | string | Tất cả, khi được đặt | Giá trị config `provider` |
| `labels.service_name` | string | Tất cả, khi được đặt | Giá trị config `service_name` |

### Tương thích SIEM

ECS payload có thể dùng ngay với:

- **Elastic SIEM**: schema là native; không cần remapping
- **Wazuh**: template wazuh-indexer nhận trực tiếp các sự kiện dạng ECS
- **Sumo Logic, Datadog, Graylog, Loki**: schema linh hoạt; index bất kỳ JSON nào bạn gửi

Cần một bước mapping một lần (Vector / Logstash / Filebeat processor, hoặc pipeline riêng của SIEM) cho:

- **Splunk**: cài [Add-on for Elastic Common Schema] để ánh xạ ECS sang Splunk CIM, hoặc POST lên HEC và viết một Splunk macro tuân theo CIM
- **Microsoft Sentinel**: viết một [KQL parse function](https://learn.microsoft.com/azure/sentinel/normalization-about-parsers) dịch ECS sang ASIM
- **AWS Security Hub**: dịch sang [ASFF] trước khi chuyển tiếp

Đối với các SIEM doanh nghiệp cũ ưa dùng CEF (ArcSight) hoặc LEEF (IBM QRadar), dùng Vector hoặc Logstash để remap các trường ECS. (Chế độ output CEF native nằm trong roadmap nếu có đủ nhu cầu.)

[Add-on for Elastic Common Schema]: https://splunkbase.splunk.com/app/4848
[ASFF]: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html

### Kiến trúc production

Hầu hết SIEM production không nhận webhook trực tiếp. Luồng thông thường là:

```
pamsignal --HTTPS--> ingest layer (Vector / Fluent Bit / Logstash) --> SIEM
```

pamsignal chỉ gửi tới URL `https://`, nên ingest layer phải terminate TLS bằng một certificate mà curl tin cậy (trust store của hệ thống, hoặc `webhook_ca_bundle`). Ví dụ cấu hình Vector nhận từ pamsignal và chuyển tiếp đến Elastic:

```toml
[sources.pamsignal]
type = "http_server"
address = "0.0.0.0:8443"
encoding = "json"
tls.enabled = true
tls.crt_file = "/etc/vector/tls/server.crt"
tls.key_file = "/etc/vector/tls/server.key"

[sinks.elastic]
type = "elasticsearch"
inputs = ["pamsignal"]
endpoints = ["https://es.example.com:9200"]
api_version = "v8"
```

Cùng pattern này áp dụng cho bất kỳ SIEM nào không dùng ECS: thêm bước `transforms.remap` giữa source và sink để đổi tên trường.

## Cơ chế cách ly cảnh báo hoạt động như thế nào

Xem [Architecture: Alert isolation model](./architecture.md#mô-hình-cô-lập-cảnh-báo) để có giải thích đầy đủ. Tóm tắt:

1. Sự kiện **luôn được ghi vào journal trước** (bản ghi cốt lõi được lưu trữ)
2. Tiến trình cha `fork()` một tiến trình con
3. Tiến trình con `execv("/usr/bin/curl", ...)` gửi HTTPS request
4. Tiến trình cha tiếp tục event loop ngay lập tức mà không chờ đợi
5. Nếu tiến trình con bị crash hoặc mạng bị ngắt, tiến trình cha không bị ảnh hưởng
6. Không có HTTP library nào tồn tại trong tiến trình cha
