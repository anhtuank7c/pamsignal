![License](https://img.shields.io/github/license/anhtuank7c/pamsignal)
![Language](https://img.shields.io/badge/Language-C-orange)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)

# PAMSignal

## Giới thiệu

Các quản trị viên thường bị động trước các cuộc xâm nhập trái phép do hệ thống log mặc định quá khó theo dõi, dễ bị xóa bỏ, hoặc các công cụ bảo mật hiện có quá nặng nề và phức tạp để triển khai trên các máy chủ cấu hình thấp, hoặc chỉ đơn giản là bạn không có đủ ngân sách, không đủ nhân lực để ứng dụng các hệ thống khổng lồ như EDR (**E**ndpoint **D**etection and **R**esponse), XDR (**E**xtended **D**etection and **R**esponse) vốn chỉ dành cho doanh nghiệp lớn, chuyên nghiệp.

**Lý do tôi tạo ra PAMSignal**

- Bản thân tôi cũng gặp khá nhiều rắc rối cũng như trở ngại khi phải quản lý một số lượng tương đối máy chủ linux với **nguồn lực hạn chế**.
- Mong muốn thực hành lập trình C nhiều hơn, thành thục và giỏi kỹ năng này.
- Mong muốn kết nối, học hỏi từ những chuyên gia trong ngành (gồm cả trong và ngoài nước).
- Muốn tìm hiểu sâu hơn về Linux.
- Tạo ra sản phẩm mã nguồn mở Made in Vietnam.

**PAMSignal là gì?**

PAMSignal là một ứng dụng dành riêng cho Linux dùng giám sát và cảnh báo ngay khi xuất hiện các phiên đăng nhập. Đảm bảo bạn luôn chủ động trong mọi tình huống.

**Có chạy được trên Mac không?**

Hiện tại tôi ưu tiên tối ưu tuyệt đối cho **Linux Server** – nơi mà mỗi giây mỗi phút đều đối mặt với hàng ngàn đợt tấn công. Tôi muốn PAMSignal phải là 'lưỡi dao sắc nhất' trên Linux trước khi nghĩ đến việc mang nó sang các hệ điều hành khác như MacOS. Với tôi, bảo mật server là ưu tiên số 1!

**Ai cần dùng PAMSignal?**

Nhiều anh em hỏi tôi: Sao không dùng Wazuh hay cài EDR, XDR cho chuyên nghiệp?

Câu trả lời đơn giản là: **Chiếc xe tải không phải lúc nào cũng tốt hơn chiếc xe máy khi bạn chỉ cần đi chợ.**

Vậy **PAMSignal** phù hợp với ai?

PAMSignal tập trung vào giám sát truy cập (Access Monitoring) vậy nên bạn sẽ cần dùng tới PAMSignal nếu như:

* Bạn cần quản trị 1-10 vps/server linux (hoặc hơn thế nữa).
* Bạn có server cấu hình tối thiểu nhưng vẫn muốn giám sát.
* Bạn cần một công cụ giám sát truy cập vừa đủ đơn giản, nhỏ nhẹ, không cần backend, hoàn toàn miễn phí.
* Bạn ưu tiên sự tối giản, cài đặt là dùng (plug & play), không cần tốn thời gian đọc hàng trăm trang tài liệu.
* Bạn cần công cụ có thể gửi cảnh báo tới Telegram/Slack/custom webhook (tích hợp thẳng vào web của bạn).
* Bạn cần công cụ miễn phí phân phối sử dụng giấy phép mã nguồn mở MIT.

**Vì sao dùng C làm ngôn ngữ chính lập trình PAMSignal?**

PAMSignal được viết bằng C thuần để đảm bảo không phụ thuộc vào các runtime cồng kềnh (như Python hay Java), giúp giảm thiểu tối đa diện tích tấn công (attack surface) cho chính nó, và cũng đơn giản hóa quá trình cài đặt, luôn giữ dung lượng cài đặt ở mức tối thiểu.

## Project Roadmap

Tôi chia dự án thành 3 giai đoạn chính để đảm bảo tính khả thi và bền vững:

### Giai đoạn 1: The Core Observer (Nền tảng hệ thống)

* [ ] Initialize: Cấu trúc dự án C, quản lý dependency bằng Makefile.
* [ ] Journal Subscriber: Sử dụng *libsystemd* để lắng nghe luồng sự kiện auth.
* [ ] PAM Logic: Lọc chính xác các sự kiện *session opened* và *session closed*.
* [ ] Information Extractor: Trích xuất các trường dữ liệu: User, Remote IP, Service (sshd/sudo/su).

### Giai đoạn 2: Context Awareness (Làm giàu thông tin)

* [ ] **Network Discovery:**  Liệt kê toàn bộ IP hiện có của máy chủ.
  * Truy vấn `/proc/net/tcp` để xác định **Destination IP** (IP mà khách đang kết nối tới).
* [ ] **Provider Identity:** Tích hợp logic nhận diện nhà cung cấp Cloud (AWS, GCP, DigitalOcean, v.v.).
* [ ] **ASN/Organization Lookup:** Lấy tên ISP của người đang truy cập (Ví dụ: Viettel, FPT, hay một trung tâm dữ liệu lạ ở Nga).
* [ ] **Message Templating:** Thiết kế cấu trúc thông báo chuyên nghiệp, dễ đọc.

### Giai đoạn 3: The Dispatcher & Distribution (Phát hành)

* [ ] **Multi-channel Alert:** Tích hợp `libcurl` để gửi thông báo qua Telegram/Slack API.
* [ ] **Config Manager:** Xây dựng file cấu hình (YAML hoặc JSON) để người dùng tùy biến.
* [ ] **Snap Packaging:** Đóng gói ứng dụng dưới dạng Snap để hỗ trợ cài đặt trên mọi Distro Linux (Ubuntu, CentOS, Fedora...).
* [ ] **Official Release:** Đưa lên Snap Store toàn cầu.
