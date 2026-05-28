# Bước 1 - Khởi Tạo (Project Initialization)

> 🌐 [English](../../notes/project-initialization.md) · **Tiếng Việt**

- **Trạng thái**: Hoàn thành
- **Ngày bắt đầu**: 26/12/2025
- **Ngày hoàn thành**: 26/12/2025
- **Ngày cập nhật**: 20/02/2026

## 1. Mục Tiêu

Thiết lập nền tảng cho project **PAMSignal**. Đảm bảo mã nguồn được tổ chức khoa học, dễ mở rộng, và có quy trình build tự động với hiệu năng được tối ưu.

## 2. Yêu Cầu

**Hệ Điều Hành**

Vì project tập trung vào Linux và yêu cầu thư viện **libsystemd**, để chạy project này bạn cần sử dụng hệ điều hành Linux, chẳng hạn Ubuntu hoặc bất kỳ distro nào khác.

**Tại sao chọn Meson build system?** [xem chi tiết tại đây](./phase-1-meson_guide.md)

**Tài liệu Meson** [xem chi tiết tại đây](https://mesonbuild.com/Quick-guide.html)

**Dependencies**

```bash
sudo apt update
sudo apt install libsystemd-dev pkg-config build-essential meson ninja-build
```

Sau khi cài đặt, bạn có thể clone project và chạy các lệnh `meson` và `ninja`. Kết quả đầu ra sẽ là file thực thi `pamsignal` nằm trong `build/`.

```bash
git clone git@github.com:anhtuank7c/pamsignal.git
cd pamsignal
meson setup build
meson compile -C build
```

## 3. Cấu Trúc Thư Mục

```
pamsignal
    src/            Chứa mã nguồn thực thi (.c)
    include/        Chứa các header file (.h) để quản lý interface.
    meson.build     Quản lý quy trình build.
    docs/           Quản lý tài liệu
```

## 4. Tối Ưu Hóa Biên Dịch Với Meson

Trình biên dịch C có nhiều tùy chọn liên quan đến tối ưu hóa mã máy [xem chi tiết tại đây](https://gcc.gnu.org/onlinedocs/gcc-15.1.0/gcc/Optimize-Options.html)

Theo mặc định trong `meson.build`, tôi đã chỉ định `'buildtype=release'` làm tùy chọn mặc định. Trong Meson, kiểu build `release` tự động áp dụng mức tối ưu hóa `-O3` và loại bỏ các debug symbols.

**Tại sao chọn chế độ Release?**

Đây là kiểu build tối ưu hóa giúp trình biên dịch sắp xếp lại các lệnh máy, loại bỏ mã dư thừa, và tăng tốc độ xử lý log đáng kể so với các bản debug build.

## 5. Kết Quả

- [x] Khởi tạo cấu trúc thư mục thành công.

- [x] Cấu hình Meson hoạt động tốt, phát hiện thư viện `libsystemd` chính xác.

- [x] Biên dịch thành công file thực thi đầu tiên (Sanity Check).
