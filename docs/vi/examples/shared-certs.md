# Shared mTLS Demo Certs

> 🌐 [English](../../../examples/shared-certs/README.md) · **Tiếng Việt**

Một CA + server cert + client cert tự chứa dùng chung cho cả ba example project để minh họa đường dẫn mTLS của webhook PAMSignal. **Chỉ dùng cho local/demo — không bao giờ dùng các cert này trong production.**

## Nội dung

| File | Đã commit? | Mô tả |
|---|---|---|
| `gen-test-certs.sh` | ✅ | Script tạo cert — sinh ra sáu file bên dưới |
| `README.md` | ✅ | File này |
| `.gitignore` | ✅ | Bỏ qua các file `*.crt`, `*.key`, `*.csr`, `*.srl` đã tạo |
| `ca.crt`, `ca.key` | ❌ | Root CA tự ký, dùng bởi cả hai receiver để xác thực client cert |
| `server.crt`, `server.key` | ❌ | Danh tính server (`CN=localhost`, `SAN=DNS:localhost,IP:127.0.0.1`) dùng bởi cả hai receiver |
| `client.crt`, `client.key` | ❌ | Danh tính client, được trình bởi `curl` từ PAMSignal, bởi Bruno, và bởi bộ test |

## Cách kết nối

Mỗi consumer tạo symlink đường dẫn `certs/` của nó về đây:

```
examples/shared-certs/                       ← real files live here
        ▲
        ├── examples/python-webhook/certs    (symlink)
        ├── examples/nodejs-webhook/certs    (symlink)
        └── examples/bruno-collection/certs  (symlink)
```

Các receiver tham chiếu `./certs/server.{crt,key}` và `./certs/ca.crt` trong `.env` của chúng; mục Client Certs của Bruno trỏ đến `certs/client.{crt,key}` tương đối với thư mục gốc của collection. Các symlink làm cho cả ba đường dẫn đều phân giải về đây. Chạy `gen-test-certs.sh` một lần là đã cấp cert cho tất cả cùng lúc.

## Cách dùng

```bash
# From this directory:
./gen-test-certs.sh

# Or with a custom output dir (rarely needed):
./gen-test-certs.sh /tmp/some-other-place
```

Sau khi tạo xong, hãy khởi động lại bất kỳ receiver nào đang chạy — Werkzeug/Express đã nạp cert cũ vào bộ nhớ khi khởi động và sẽ không reload cho đến khi được khởi động lại:

```bash
# Python:
cd ../python-webhook && uv run python src/server.py
# Node:
cd ../nodejs-webhook && pnpm run dev
```

## Tại sao dùng một CA dùng chung thay vì mỗi receiver một CA?

Mỗi lần gọi `gen-test-certs.sh` sẽ tạo ra một CA tự ký **độc lập**. Nếu Python và Node mỗi cái chạy script riêng, các CA tạo ra sẽ khác nhau, và một client cert từ cái này sẽ không xác thực được với cái kia. Dùng chung đơn giản hóa việc kiểm thử chéo — tạo một lần, cả hai receiver chấp nhận cùng cert của Bruno (và curl), không cần hoán đổi symlink khi chuyển đổi giữa chúng.

## Cấu hình cho môi trường production

Thay thế nội dung thư mục này bằng các đường dẫn được quản lý bởi cert pipeline của bạn (cert-manager, certbot, internal CA + ACME, `systemd-creds`, v.v.). Bốn env var `TLS_*` và các config key `webhook_*` trong `pamsignal.conf` vẫn như cũ; chỉ có nội dung file thay đổi. Các symlink trong các consumer project có thể giữ nguyên hoặc thay bằng đường dẫn tuyệt đối — tùy theo deployment của bạn.
