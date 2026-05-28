# PAMSignal Webhook Bruno Collection

> 🌐 [English](../../../examples/bruno-collection/README.md) · **Tiếng Việt**

Các request [Bruno](https://www.usebruno.com/) sẵn dùng để kiểm thử bất kỳ webhook receiver PAMSignal nào — [ví dụ Node.js](nodejs-webhook.md), [ví dụ Python](python-webhook.md), hoặc bất kỳ triển khai nào khác theo cùng contract `POST /webhook/pamsignal`.

Đã kiểm thử với **Bruno ≥ 3.3.0**.

## Mục lục

- [Bắt đầu nhanh](#bắt-đầu-nhanh) — nhận 200 OK đầu tiên trong năm bước
- [Environments](#environments) — HTTP so với mTLS
- [Gửi request đầu tiên](#gửi-request-đầu-tiên) — hướng dẫn giao diện
- [Kiểm thử khả năng phòng thủ của receiver](#kiểm-thử-khả-năng-phòng-thủ-của-receiver) — cố tình kích hoạt 401 / 415 / 413 / 400
- [Thiết lập mTLS](#thiết-lập-mtls) — quy trình client cert + CA tự ký
- [Tùy chỉnh collection](#tùy-chỉnh-collection) — chỉnh sửa payload, thêm request, ghi đè từng request
- [Xử lý sự cố](#xử-lý-sự-cố)

## Bắt đầu nhanh

1. Cài đặt [Bruno](https://www.usebruno.com/).
2. Click **Open Collection** (không phải *Import Collection* — đường dẫn đó dùng cho Postman/OpenAPI JSON và sẽ thất bại với lỗi *"Unsupported collection format"*). Chọn thư mục `examples/bruno-collection`.
3. Khởi động một trong các receiver mẫu trong terminal khác:
   ```bash
   # Python
   cd ../python-webhook && uv run python src/server.py
   # or Node.js
   cd ../nodejs-webhook && pnpm run dev
   ```
4. Trong Bruno, chọn environment **Local** từ dropdown góc trên bên phải và click **biểu tượng mắt** để chỉnh sửa. Đặt `WEBHOOK_SECRET` thành giá trị bạn đã đặt trong `.env` của receiver.
5. Mở request **Login Success** và click **Send**. Bạn sẽ thấy `200 OK` với `{"status":"success","message":"Event received"}`.

Nếu bạn nhận được kết quả đó, collection đã được kết nối đúng. Phần còn lại của README này giải thích cách kiểm thử receiver kỹ lưỡng hơn.

## Environments

| Environment | URL | Dùng khi |
|---|---|---|
| **Local** | `http://localhost:3000/webhook/pamsignal` | Receiver đang chạy trên plain HTTP |
| **Local-mTLS** | `https://localhost:3000/webhook/pamsignal` | Receiver có `TLS_REQUIRE_CLIENT_CERT=true` (xem [thiết lập mTLS](#thiết-lập-mtls)) |

Cả hai đều dùng chung hai biến — `WEBHOOK_URL` và `WEBHOOK_SECRET` — mà mọi request đều tham chiếu qua `{{...}}`. Chuyển đổi environment chỉ cần một click vào dropdown; không cần chỉnh sửa request.

## Gửi request đầu tiên

1. Mở **Login Success** trong sidebar. Bạn sẽ thấy:
   - Panel **URL**: `{{WEBHOOK_URL}}` — được nội suy lúc gửi từ environment đang hoạt động.
   - Tab **Auth**: Bearer scheme, token `{{WEBHOOK_SECRET}}`.
   - Tab **Body**: một tài liệu JSON có dạng ECS tổng hợp mô tả một event `login_success`.
2. Click **Send**.
3. Panel **Response** hiển thị:
   - **Status**: `200 OK`
   - **Body**: `{"status":"success","message":"Event received"}`
   - **Headers**: `Content-Type: application/json`
   - **Timeline**: thời gian round-trip, kích thước request/response
4. Chuyển sang terminal của receiver — bạn sẽ thấy dòng log tương ứng:
   ```
   ✅ [LOGIN_SUCCESS] User 'admin' logged in via 10.0.0.1 on server-01 (PID: 1234)
   ```

Hai request cần sẵn còn lại (`Login Failure`, `Brute Force Detected`) hoạt động tương tự với các dạng payload khác nhau và tạo ra các tiền tố log khác nhau ở phía receiver.

## Kiểm thử khả năng phòng thủ của receiver

Receiver triển khai nhiều kiểm tra phòng thủ (xác thực, giới hạn kích thước body, Content-Type, hình dạng payload). Bạn có thể xác minh từng cái bằng cách cố tình phá một request và quan sát mã response. Mỗi hàng là một bài kiểm tra 30 giây:

| Phòng thủ | Cách phá request | Response mong đợi |
|---|---|---|
| **Bearer auth** | Trong env, xóa `WEBHOOK_SECRET` (hoặc mở request → tab **Auth** → tạm thời đổi token). Gửi. | `401 {"error":"Unauthorized: Invalid or missing token"}` |
| **Bearer auth (sai scheme)** | Tab Auth → chuyển từ *Bearer* sang *Basic*. Gửi. | `401` |
| **Content-Type** | Tab **Body** → chuyển loại từ *JSON* sang *Text*. Giữ nguyên nội dung body. Gửi. | `415 {"error":"Unsupported Media Type: expected application/json"}` |
| **Giới hạn kích thước body (64 KB)** | Tab Body → trong JSON, thêm một trường chuỗi dài, ví dụ: `"pad": "AAA…"` lặp lại khoảng 70 KB. Gửi. | `413 Payload Too Large` |
| **Hình dạng payload** | Tab Body → xóa block `"event"` hoặc `"pamsignal"` khỏi JSON. Gửi. | `400 {"error":"Bad Request: Invalid payload format"}` |
| **Thứ tự xác thực trước validation** | Xóa `WEBHOOK_SECRET` *và* chuyển loại Body sang Text. Gửi. | `401` (không phải `415`) — receiver xác thực trước khi kiểm tra media type, vì vậy các peer chưa xác thực không thể biết gì về content negotiation của endpoint. |
| **mTLS handshake** | (Env Local-mTLS) → collection **Settings → Client Certs** → xóa mục cert localhost. Gửi. | Lỗi TLS handshake (Bruno hiển thị *"alert certificate required"* hoặc tương tự — request không bao giờ đến HTTP). Thêm lại cert để phục hồi. |

Nếu bất kỳ cái nào trong số này trả về status khác với bảng, bạn đã tìm thấy lỗi trong receiver hoặc sự khác biệt thực sự giữa hai ví dụ triển khai — cả hai đều đáng điều tra.

Bruno giữ một tab **History** cho mỗi request, vì vậy bạn có thể chuyển qua lại giữa phiên bản bị phá và phiên bản đúng để so sánh chúng cạnh nhau.

## Thiết lập mTLS

Bruno 3.x lưu trữ cấu hình client-certificate trong giao diện, không trong các file được kiểm soát phiên bản, vì vậy đây là thiết lập một lần cho mỗi máy.

### Bước 1 — tạo cert demo

`certs/` của collection là một symlink đã commit đến [`../../../examples/shared-certs/`](../../../examples/shared-certs/). Tạo các file thực tế một lần bằng shared script — cả hai webhook receiver đều lấy cùng output qua các symlink `certs/` của riêng chúng, vì vậy bạn không bao giờ phải chuyển đổi thủ công giữa các thiết lập Python/Node:

```bash
# From the repo root:
(cd examples/shared-certs && ./gen-test-certs.sh)
```

Sau đây, `examples/bruno-collection/certs/client.crt` (được phân giải qua symlink) tồn tại và Bruno có thể nạp nó.

### Bước 2 — đăng ký client cert trong Bruno

Click tên collection (sidebar trái) → **Settings** → tab **Client Certs** → **Add Client Certificate**:

| Trường | Giá trị |
|---|---|
| Domain | `127.0.0.1` |
| Type | `cert` (PEM cert + PEM key) |
| Cert file path | `certs/client.crt` |
| Key file path | `certs/client.key` |
| Passphrase | *(để trống)* |

Lưu lại. Bruno sẽ trình `certs/client.crt` + `certs/client.key` mỗi khi host của một request khớp với `127.0.0.1`.

> Tại sao dùng `127.0.0.1` mà không phải `localhost`? Ví dụ Python bind chỉ IPv4 (`run_simple("0.0.0.0", ...)`), và macOS phân giải `localhost` thành `::1` (IPv6) trước — kết nối thất bại với `ECONNREFUSED ::1:3000`. Các file env được cung cấp sử dụng `127.0.0.1` để tránh vấn đề này; SAN của demo server cert bao gồm `IP:127.0.0.1`, vì vậy TLS vẫn xác thực. Nếu bạn đã đổi env thành `localhost` và server của bạn bind dual-stack (ví dụ Node thì có), hãy đăng ký cert với `localhost` thay thế — hoặc thêm cả hai mục.

### Bước 3 — chấp nhận demo CA tự ký

CA được tạo bởi `gen-test-certs.sh` không có trong OS trust store của bạn, vì vậy Bruno sẽ từ chối TLS handshake theo mặc định. Tắt xác thực:

- Tên collection → **Settings → Proxy** (hoặc **Network**, tên có thể khác) → bật/tắt **SSL Verification off**.
- Hoặc, theo từng request: biểu tượng bánh răng bên cạnh URL → bỏ chọn **SSL Verification**.

Đối với deployment production với cert do CA ký, hãy giữ xác thực bật.

### Cách hoạt động (một đoạn tóm tắt)

mTLS xảy ra ở lớp TLS *trước khi* bất kỳ HTTP nào được trao đổi. Server (Werkzeug/Express) trình cert của nó và yêu cầu client cert; Bruno trình `client.crt` + ký transcript handshake bằng `client.key`; server xác thực cert đó với CA pool của nó (`certs/ca.crt`); chỉ sau đó request mới đến handler của bạn, nơi Bearer-token auth chạy như một lớp thứ hai, độc lập. Thiếu client cert = lỗi TLS handshake (không có HTTP response). Bearer token sai nhưng client cert hợp lệ = `401`. Hai lớp độc lập với nhau — đó chính là ý nghĩa của bảo mật theo chiều sâu.

## Tùy chỉnh collection

### Chỉnh sửa body của một request

Mở bất kỳ request nào → tab **Body** → chỉnh sửa JSON inline. Bruno hiển thị nó với JSON editor; lỗi cú pháp được tô sáng. Body được gửi nguyên văn, vì vậy bạn có thể thử nghiệm với các trường hợp biên (chuỗi rất dài, unicode, ký tự điều khiển nhúng) để xem receiver của bạn xử lý chúng như thế nào.

### Thêm một request mới

Click chuột phải vào collection trong sidebar → **New Request**. Dùng cùng template:

```
post {
  url: {{WEBHOOK_URL}}
  body: json
  auth: bearer
}

auth:bearer {
  token: {{WEBHOOK_SECRET}}
}

body:json {
  {
    "event": { "action": "your_new_action" },
    "pamsignal": {}
  }
}
```

Bruno sẽ lưu nó như `<Name>.bru` cạnh các file khác. `seq:` trong block `meta` điều khiển thứ tự sắp xếp trong sidebar.

### Ghi đè giá trị env theo từng request

Đôi khi bạn muốn một request dùng URL hoặc secret khác (ví dụ: để kiểm thử một staging endpoint). Mở request → tab **Vars** → thêm biến `Pre-request`. Các biến được định nghĩa ở đây sẽ che khuất các env var cho request đó.

### Chuyển đổi nhanh giữa Python và Node receiver

Cả hai receiver đều mặc định dùng cổng 3000, vì vậy không cần thay đổi gì — khởi động cái bạn muốn kiểm thử rồi gửi. Để kiểm thử cả hai cùng lúc, hãy chỉnh sửa các file env để dùng cổng khác nhau (ví dụ: `Local-Node` trên `:3000`, `Local-Python` trên `:3001`) và chạy receiver tương ứng trên cổng phù hợp.

## Xử lý sự cố

| Triệu chứng | Nguyên nhân có thể | Cách sửa |
|---|---|---|
| *"Unsupported collection format"* khi mở | Bạn đã click **Import Collection** thay vì **Open Collection** | Dùng **Open Collection** — thư mục đã ở định dạng `.bru` gốc của Bruno và không cần chuyển đổi |
| Biến hiển thị `{{WEBHOOK_SECRET}}` theo nghĩa đen trong response/timeline | Chưa chọn environment, hoặc env thiếu biến đó | Chọn env từ dropdown (góc trên phải); xác nhận cả `WEBHOOK_URL` và `WEBHOOK_SECRET` đều được định nghĩa |
| `ECONNREFUSED ::1:3000` | Env dùng `localhost`, nhưng receiver bind chỉ IPv4 (Python's `run_simple("0.0.0.0", ...)`); macOS phân giải `localhost` thành `::1` trước | Dùng `127.0.0.1` trong URL của env (các env đi kèm đã làm vậy); nếu bạn cũng đã cấu hình Client Cert với `localhost`, hãy cập nhật **Domain** của nó thành `127.0.0.1` để khớp |
| `ECONNREFUSED` / "Failed to connect" (bất kỳ cổng/host nào khác) | Receiver không chạy, sai cổng, hoặc sai scheme (HTTP so với HTTPS env) | `curl -v {{WEBHOOK_URL}}` bên ngoài Bruno để xác nhận; kiểm tra xem scheme URL của env có khớp với những gì receiver đang lắng nghe không |
| `401 Unauthorized` không mong muốn | `WEBHOOK_SECRET` của env không khớp với `.env` của receiver | Cập nhật một trong hai để khớp; khởi động lại receiver nếu bạn đã đổi `.env` (nó đọc khi khởi động) |
| `TLS handshake / alert certificate required` | Đã chọn env mTLS nhưng chưa đăng ký client cert trong Bruno, hoặc `gen-test-certs.sh` chưa được chạy, hoặc symlink target bị hỏng | Chạy `(cd ../shared-certs && ./gen-test-certs.sh)`; kiểm tra lại mục **Client Certs**; xác minh `ls -L certs/client.crt` trỏ đến file thực |
| `SELF_SIGNED_CERT_IN_CHAIN` / không thể xác minh cert | mTLS hoạt động nhưng SSL verification vẫn bật cho demo CA | Bật/tắt **SSL Verification off** cho demo (Bước 3 ở trên); đối với production, cài đặt CA thực |
| `Parse Error: Expected HTTP/, RTSP/ or ICE/` | Sai scheme: Bruno gửi plain HTTP nhưng receiver phản hồi bằng TLS bytes (một TLS alert được đọc như rác bởi HTTP parser của Node) | Hoặc chuyển sang env **Local-mTLS**, hoặc comment out các dòng `TLS_*` trong `.env` của receiver và khởi động lại. Xác nhận với `curl -v http://localhost:3000/...` — nếu bạn thấy *"Received HTTP/0.9 when not allowed"*, server đang chạy HTTPS. |
| Request "treo" khi Send | Tiến trình receiver bị crash hoặc bị block | Kiểm tra terminal của receiver để tìm stack trace; khởi động lại |

Nếu có gì đó kỳ lạ khác xảy ra, tab **Timeline** của Bruno (cạnh *Response*) hiển thị toàn bộ trao đổi HTTP bao gồm request line, header, byte body và thời gian. Thường đủ để phát hiện sự không khớp.
