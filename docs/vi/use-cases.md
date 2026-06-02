# Use Cases & Tích hợp

> 🌐 [English](../use-cases.md) · **Tiếng Việt**

PAMSignal cố tình nhỏ. Nó làm **một** việc — theo dõi các sự kiện PAM authentication rồi báo cho bạn — và nó nói những định dạng mở, chuẩn (entry journal có cấu trúc và JSON [ECS](https://www.elastic.co/guide/en/ecs/current/index.html)), nên lắp vào được bất cứ thứ gì bạn đang chạy thay vì trở thành thêm một console nữa phải trông chừng.

Trang này trả lời hai câu hỏi: **ai được lợi từ PAMSignal**, và **làm sao lắp nó vào một stack sẵn có**.

> **Nhắc lại về phạm vi.** PAMSignal là tầng *phát hiện và cảnh báo*. Nó không ngăn đăng nhập, không chặn IP, không quét file, và không thay thế một SOC. Nó đi cùng các công cụ làm những việc đó — xem [Bảo mật SSH](ssh-hardening.md) (phòng ngừa), [Fail2ban](examples/fail2ban.md) (phản ứng), và [Threat Model](threat-model.md) để biết chính xác nó thấy và không thấy gì.

---

## PAMSignal dành cho ai

### Lập trình viên cá nhân / self-hoster

Bạn chạy 1–5 VPS cá nhân, một homelab, hay một dự án phụ. Bạn không muốn dựng Wazuh hay đọc 200 trang tài liệu EDR — bạn chỉ muốn **biết ngay khoảnh khắc có người đăng nhập vào máy mình, hoặc bắt đầu thử**.

**Một cấu hình hợp lý:**
- Cài qua dòng lệnh ở [Bắt đầu nhanh](README.md#-bắt-đầu-nhanh).
- Thêm một kênh [Telegram](alerts.md#telegram) hoặc [Discord](alerts.md) — xong trong hai phút.
- Đặt `enable_notification_type = login_success,brute_force` để chỉ bị ping về đăng nhập thành công và tấn công, chứ không phải mọi sự kiện.
- Thêm [Fail2ban](examples/fail2ban.md) nếu muốn tự động ban kẻ brute-force.

**Bạn được gì:** điện thoại rung lên khi bạn (hoặc bất kỳ ai) đăng nhập thành công, và khi một con bot bắt đầu dò máy bạn. Đó là 90% sự an tâm với 0% gánh nặng vận hành.

### Nhóm nhỏ / vận hành startup

Bạn chạy 5–30 server, dùng chung một lịch on-call, và đã có sẵn một workspace Slack hoặc Teams.

**Một cấu hình hợp lý:**
- Triển khai ra cả fleet bằng [Ansible playbook](ssh-hardening.md#32-cách-tái-lập-được-ansible), dùng chung một `pamsignal.conf`.
- Định tuyến alert về một kênh [Slack/Teams](alerts.md) **#security-alerts** riêng.
- Dựng [Grafana fleet dashboard](grafana-getting-started.md) để ai trực on-call cũng thấy cả fleet trong một cái nhìn.
- Nếu đã có SIEM, forward sự kiện vào đó qua [custom webhook](#đã-chạy-một-siem-elastic--wazuh--splunk--datadog).

**Bạn được gì:** cả đội nhìn chung một luồng tức thì và một dashboard toàn fleet; không ai phải grep `journalctl` trên từng host giữa lúc xử lý sự cố.

### Hosting provider nhỏ / MSP

Bạn chạy server *cho người khác* — shared hosting, bán lại VPS, dedicated box có quản lý, hoặc một hợp đồng dịch vụ quản lý. Khả năng quan sát hoạt động auth là thứ khách hàng muốn nhưng hiếm khi tự làm, và PAMSignal cho phép bạn cung cấp nó như một **giá trị gia tăng gần như không tốn chi phí**: nó chỉ là một C binary nhỏ, chỉ phụ thuộc `libsystemd`, cảnh báo qua `fork+exec curl` ngắn ngủi, và không thêm tải đáng kể lên VPS khách hàng. Bạn có thể đặt nó lên mọi máy mình quản lý.

Đây là playbook đầy đủ.

#### 1. Gắn tag cho từng host để alert tự nhận diện

Đặt hai key context-tag trong `pamsignal.conf` của mỗi host (template theo từng host bằng [Ansible](ssh-hardening.md#32-cách-tái-lập-được-ansible)):

```ini
provider = acme-cloud
service_name = cust-1042-web01
```

Giờ mọi alert và webhook payload đều mang theo `provider=acme-cloud service_name=cust-1042-web01`, nên dù tất cả đổ về một chỗ, bạn vẫn luôn biết một alert đến từ *khách hàng nào, máy nào*. (Xem [Alerts](alerts.md#định-dạng-tin-nhắn).)

#### 2. Chọn cách định tuyến alert

Config của PAMSignal là **theo từng host**, nên bạn có hai lựa chọn gọn gàng:

- **Gửi thẳng cho khách.** Đặt thông tin xác thực Telegram/Slack của chính khách hàng vào config trên các host *của họ*. Mỗi khách được cảnh báo về server của mình một cách trực tiếp — một tính năng hữu hình mà họ thấy chạy.
- **Gom về NOC.** Gửi mọi host về kênh/webhook vận hành của bạn, rồi cho khách một góc nhìn [Grafana](grafana-getting-started.md) chỉ-đọc (mục dưới). Hợp hơn khi *bạn* mới là người xử lý.

Bạn có thể trộn cả hai: ping hướng-tới-khách cho các ca thành công/brute-force, còn toàn bộ firehose thì đổ về NOC.

#### 3. Cho mỗi khách một góc nhìn dashboard riêng

Grafana sinh ra để làm multi-tenant. Chọn mức cô lập khớp với mô hình kinh doanh của bạn:

- **Dashboard / folder theo từng khách**, với biến `$host` khóa vào các host của khách đó — đơn giản nhất, ổn khi khách không tự đăng nhập.
- **Một Grafana Organization (hoặc Grafana RBAC team) cho mỗi tenant** — cô lập thật sự; cấp cho khách một tài khoản chỉ-đọc, giới hạn phạm vi để họ chỉ thấy host của chính mình.

Vì tên host và tag `service_name` của bạn vốn đã là label/trường sẵn, việc giới hạn một góc nhìn cho một khách chỉ là một bộ lọc, không phải một dự án tách dữ liệu.

#### 4. Đưa nó vào portal của chính bạn (white-label)

Trỏ [custom webhook](configuration.md#xác-thực-custom-webhook) về backend control-panel của bạn. PAMSignal POST [ECS JSON](alerts.md#custom-webhook-ecs-json) cho mọi sự kiện; backend của bạn lưu lại và render một widget "**Đăng nhập gần đây & tấn công đã chặn**" ngay trong dashboard sẵn có của khách — hoàn toàn theo thương hiệu của bạn. Hai ví dụ webhook [Node.js](examples/nodejs-webhook.md) và [Python](examples/python-webhook.md) là những receiver chạy được mà bạn có thể phát triển tiếp.

#### 5. Đóng gói thành một gói dịch vụ

- **Miễn phí / kèm sẵn:** alert brute-force + root-login thời gian thực gửi cho khách.
- **Add-on trả phí:** fleet dashboard, [audit retention](grafana-getting-started.md#chi-phí--lưu-ý) 90 ngày (hoặc 1 năm) trong Loki, và một báo cáo "hoạt động auth & tấn công đã chặn" hằng tháng. Dữ liệu vốn đã chảy sẵn; cái bạn bán thêm chỉ là phần đóng gói.

#### 6. Biết rõ — và nói rõ — giới hạn

Hãy thành thật với khách về việc đây là gì, để nó luôn là một tính năng chứ không bao giờ thành một trách nhiệm pháp lý:

- Nó phủ các **kênh PAM-stack** — SSH, sftp, sudo, su, console login. Nó **không** thấy VPN, web console của nhà cung cấp cloud, đăng nhập control-panel, hay container exec. ([Threat Model — Phạm vi quan sát](threat-model.md#phạm-vi-quan-sát).)
- Nó là **phát hiện và cảnh báo**, không phải một SOC có quản lý, không phải antivirus/EDR, không phải WAF.
- Định vị nó cho đúng: *"Chúng tôi cảnh báo bạn trong vài giây về các lần đăng nhập SSH và tấn công brute-force lên server của bạn, và giữ lại một lịch sử tra cứu được."* Câu đó đúng, có giá trị, và đứng vững được — còn với khách cần một SOC thật thì đây là một tầng đầu tiên sạch sẽ để xây tiếp.

### Đơn vị chú trọng compliance

Nếu bạn cần *trình ra* được ai đã đăng nhập và khi nào, đường đi [Grafana + Loki](grafana-getting-started.md) cho bạn một auth trail được giữ lại, tra cứu được, có dấu thời gian trên cả fleet, còn [custom webhook](#đã-chạy-một-siem-elastic--wazuh--splunk--datadog) đẩy cùng những sự kiện đó vào một SIEM lưu hồ sơ. PAMSignal là cảm biến; chính sách retention của bạn biến nó thành một audit trail.

---

## Tích hợp vào stack sẵn có của bạn

PAMSignal là một **cảm biến (sensor)**, không phải một điểm đến. Nó phát ra hai định dạng mở — văn bản `key=value` một dòng cho chat, và [ECS JSON](alerts.md#custom-webhook-ecs-json) lồng nhau cho máy đọc — nên nó cấp dữ liệu cho các công cụ bạn đang chạy chứ không thay thế chúng.

| Nếu bạn đã chạy… | Lắp vào bằng… | Kết quả |
|---|---|---|
| Slack / Teams / Discord / Telegram / WhatsApp | Kênh native — chỉ cần thêm credential | Alert thời gian thực ngay trong chat sẵn có |
| Một SIEM (Elastic, Wazuh, Splunk, Datadog) | `webhook_url` → ECS JSON | Sự kiện rơi vào mà không cần remap trường |
| Grafana + Loki | Alloy scrape | [Dashboard auth toàn fleet](grafana-getting-started.md) |
| Fail2ban / CrowdSec | Tín hiệu journal `brute_force_detected` | Tự động chặn IP tại firewall |
| Ansible / Salt / Puppet | Package + config template | [Triển khai fleet tái lập được](ssh-hardening.md#phần-3--triển-khai-pamsignal-cho-toàn-fleet) |
| PagerDuty / Opsgenie | Grafana contact point, hoặc webhook | Paging on-call theo đúng các rule quan trọng |
| App / portal của riêng bạn | `webhook_url` → endpoint của bạn | Bất cứ thứ gì — xem các [ví dụ webhook](examples/nodejs-webhook.md) |

### Đã dùng chat (Slack / Teams / Discord / Telegram / WhatsApp)?

Đây là đường không tốn công nhất. Thả credential của kênh vào `pamsignal.conf` là xong — PAMSignal gửi tới mọi kênh có credential. Cách cài từng kênh nằm trong [Alerts](alerts.md). Lọc bớt tiếng ồn bằng [`enable_notification_type`](configuration.md#bộ-lọc-loại-thông-báo).

### Đã chạy một SIEM (Elastic / Wazuh / Splunk / Datadog)?

Trỏ `webhook_url` về endpoint ingest của bạn. PAMSignal POST một tài liệu JSON theo cấu trúc [ECS](https://www.elastic.co/guide/en/ecs/current/index.html) cho mỗi sự kiện — các object lồng nhau `event.*`, `host.*`, `user.*`, `source.*`, `service.*`, `process.*` cùng một namespace `pamsignal.*` — vốn "rơi thẳng vào Elastic SIEM và Wazuh mà không cần remap, và chỉ cách một config Vector/Logstash với bất kỳ SIEM hiện đại nào khác." Xác thực bằng [bearer header hoặc mTLS](configuration.md#xác-thực-custom-webhook):

```ini
webhook_url = https://siem.example.com/ingest/pamsignal
webhook_auth_header = Authorization: Bearer <token>
```

Payload trên đường truyền cùng một bảng các mẫu receiver (Splunk HEC, Datadog, X-API-Key, Wazuh) nằm ở [Alerts → Custom webhook](alerts.md#custom-webhook-ecs-json). Đây chính là tích hợp biến PAMSignal thành một *nguồn* trong một pipeline phát hiện lớn hơn, thay vì một công cụ đứng một mình.

### Đã chạy Grafana + Loki?

Bạn gần xong rồi — chỉ cần cài [Grafana Alloy](grafana-getting-started.md#phương-án-a--grafana-cloud-managed-zero-ops) trên mỗi host để scrape `SYSLOG_IDENTIFIER=pamsignal` từ journal, rồi import dashboard đi kèm. Hướng dẫn đầy đủ: [Grafana từ con số 0](grafana-getting-started.md).

### Đã chạy Fail2ban hoặc CrowdSec?

PAMSignal lo phần đếm; để bộ chặn của bạn ra tay dựa trên kết quả đó. [Fail2ban](examples/fail2ban.md) đọc thẳng dòng journal `BRUTE_FORCE_DETECTED` (`journalmatch = SYSLOG_IDENTIFIER=pamsignal`) — không phải bảo trì một regex `sshd` mong manh nào. Người dùng CrowdSec có thể trỏ một journald acquisition vào cùng identifier đó. PAMSignal quan sát; bộ chặn cưỡng chế; hai bên hoàn toàn tách rời.

### Đã dùng config management?

Coi PAMSignal như bất kỳ package nào khác: cài nó và template `pamsignal.conf`. [Mục triển khai fleet](ssh-hardening.md#phần-3--triển-khai-pamsignal-cho-toàn-fleet) có sẵn một Ansible playbook với context tag riêng cho từng host.

### Muốn tự xây tích hợp riêng?

[Custom webhook](configuration.md#xác-thực-custom-webhook) gửi ECS JSON tới bất kỳ URL nào. Hãy xây auto-ban, tạo ticket, widget cho portal khách hàng, hay bất cứ thứ gì khác. Khởi đầu từ ví dụ receiver [Node.js](examples/nodejs-webhook.md) hoặc [Python](examples/python-webhook.md), và dùng [bộ Bruno collection](examples/bruno-collection.md) để xem các payload thật.

---

## "Sao không dùng luôn…?"

PAMSignal không cố làm thứ duy nhất trong stack của bạn — nhưng đây là chỗ nó đứng so với các lựa chọn thường gặp:

- **…Wazuh / OSSEC / một EDR đầy đủ?** Những thứ đó tuyệt vời và rộng hơn nhiều — nhưng cũng nặng hơn nhiều (agent, một manager, một database, cả đống thứ phải tinh chỉnh). PAMSignal là đúng tầm khi bạn muốn có cảnh báo auth *ngay bây giờ* mà chưa phải dựng cả một nền tảng. Chúng cũng phối hợp được: đẩy webhook của PAMSignal vào Wazuh và dùng nó như một cảm biến nhẹ.
- **…một script `tail -f auth.log | grep`?** Mong manh giữa các distro và phiên bản `sshd`, mù với journal có cấu trúc, và bạn phải tự bảo trì nó mãi mãi. PAMSignal vốn đã hiểu sẵn các định dạng `sshd`, `sshd-session`, `sudo`, `su`, `login` rồi phát ra sự kiện có cấu trúc.
- **…cảnh báo đăng nhập của nhà cung cấp cloud?** Mấy cái đó thường chỉ phủ *cloud console*, không phải SSH/sudo ở mức OS trên instance. PAMSignal canh chừng chính cái host — và chạy y hệt nhau trên bare metal, một VPS, hay bất kỳ cloud nào.
- **…không gì cả?** Mức nền thành thật cho phần lớn server nhỏ. Cả thông điệp của PAMSignal là: nó đủ rẻ — một binary, một file config — để "không gì cả" không còn là lựa chọn dễ dãi nữa.

---

## Đọc thêm

- 🚀 **[Bắt đầu nhanh](README.md#-bắt-đầu-nhanh)** — cài đặt và alert đầu tiên
- 🔐 **[Bảo mật SSH & Quản lý Fleet](ssh-hardening.md)** — tầng phòng ngừa + triển khai fleet
- 📊 **[Grafana từ con số 0](grafana-getting-started.md)** — fleet dashboard và các mô hình multi-tenant
- 🔔 **[Alerts](alerts.md)** — các định dạng chat và payload webhook ECS JSON
- ⚙️ **[Configuration](configuration.md)** — mọi config key, gồm cả webhook auth/mTLS
- 🎯 **[Threat Model](threat-model.md)** — PAMSignal bảo vệ gì, và những kênh nó cố tình không thấy
