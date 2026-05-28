# Meson & Ninja: Công Cụ Build

> 🌐 [English](../../notes/meson-build-system.md) · **Tiếng Việt**

- **Trạng thái**: Hoàn thành
- **Ngày bắt đầu**: 20/02/2026
- **Ngày hoàn thành**: 20/02/2026

Meson và Ninja phối hợp với nhau để thay thế CMake và Make. Chúng được thiết kế để cực kỳ nhanh và thân thiện với người dùng.

* **Meson** tương đương với **CMake**: Đọc file cấu hình (`meson.build`) và sinh ra các file build.
* **Ninja** tương đương với **Make**: Đọc các file build đã được sinh ra và thực sự biên dịch mã nguồn.

## Bảng Tương Đương Các File

| CMake System           | Meson System          | Mục đích                                            |
|------------------------|-----------------------|-----------------------------------------------------|
| `CMakeLists.txt`       | `meson.build`         | Định nghĩa project, targets và dependencies         |
| `cmake -S . -B build`  | `meson setup build`   | Sinh ra các file build trong một thư mục            |
| `make`                 | `ninja`               | Thực sự biên dịch mã nguồn                          |
| `build/Makefile`       | `build/build.ninja`   | Các file được sinh ra để dùng khi biên dịch         |

## Cách Sử Dụng Meson & Ninja

Đây là quy trình chuẩn bạn sẽ dùng hàng ngày.

### 1. Cấu hình project (Chỉ làm một lần)
Lệnh này yêu cầu Meson đọc `meson.build` và tạo thư mục build.

```bash
# Cú pháp chung: meson setup <build-directory>
meson setup build
```

*Lưu ý: Bạn có thể truyền thêm các tùy chọn ở đây, như `--buildtype=release` hoặc `--buildtype=debug`.*

### 2. Build project (Làm mỗi khi thay đổi mã nguồn)
Yêu cầu Meson biên dịch các thay đổi. Nó sẽ tự động gọi Ninja bên dưới.

```bash
# Cú pháp chung: meson compile -C <build-directory>
meson compile -C build 
```

*(Hoặc bạn có thể `cd` vào thư mục build và gõ `ninja`)*

### 3. Dọn dẹp project
Với Meson, bạn thường không cần lệnh `clean`. Vì nó rất nhanh, bạn chỉ cần xóa thư mục build và cấu hình lại nếu mọi thứ trở nên lộn xộn.

```bash
rm -rf build && meson setup build
```

## Tại Sao Dùng Meson Thay Vì CMake?

1. **Cú pháp**: `meson.build` sử dụng cú pháp sạch, giống Python, dễ đọc và viết hơn `CMakeLists.txt` nhiều.
2. **Tốc độ**: Sinh ra các file build cực kỳ nhanh.
3. **Ninja theo mặc định**: Make nổi tiếng là chậm với các project lớn. Ninja được thiết kế để nhanh nhất có thể, và Meson sử dụng nó theo mặc định.
4. **Quản lý Dependencies**: Tìm và sử dụng các thư viện ngoài (như `systemd` qua `pkg-config`) thường đơn giản hơn và ít verbose hơn trong Meson.

## Tại Sao Dùng Meson Thay Vì Lệnh GCC Trực Tiếp?

Nếu bạn biên dịch project này thủ công bằng `gcc`, lệnh sẽ trông như thế này:

```bash
gcc src/init.c src/journal_watch.c src/main.c src/utils.c \
    -Iinclude -o build/pamsignal \
    $(pkg-config --cflags --libs libsystemd) \
    -Wall -Wextra -Wshadow -std=gnu17 -O2
```

Khi project phát triển, việc quản lý một lệnh duy nhất như thế này trở nên cực kỳ khó khăn:

1. **Incremental Builds**: Lệnh `gcc` trực tiếp biên dịch lại **mọi** file nguồn mỗi lần chạy, kể cả khi bạn chỉ thay đổi một dòng trong một file. Meson (thông qua Ninja) đủ thông minh để phát hiện chính xác những file nào đã thay đổi và chỉ biên dịch lại những file đó, giúp quy trình làm việc của bạn nhanh hơn đáng kể.
2. **Quản lý Độ Phức Tạp**: Thêm thư mục mới, tính năng mới, hoặc chuẩn hóa các compiler flags cho nhiều lập trình viên sẽ tạo ra một lệnh `gcc` khổng lồ, dễ xảy ra lỗi. `meson.build` tổ chức điều này một cách logic từng dòng một.
3. **Cấu hình Build**: Meson dễ dàng chuyển đổi giữa các profile (như Debug cho môi trường phát triển hay Release cho bản production) chỉ bằng cách truyền một flag (`meson setup build --buildtype=debug`). Với GCC trực tiếp, bạn phải tự thay `-O2` thành `-g -O0` và theo dõi các dependency thủ công mỗi lần.
