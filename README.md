<!-- PROJECT LOGO -->

<p align="center">
  <h3 align="center">Chương trình ECDH + AES</h3>
</p>



<!-- ABOUT THE PROJECT -->
## Giới thiệu

Chương trình triển khai thuật toán ECDH kèm với mã hoá AES với thư viện MbedTLS (PolarSSL cũ). Chương trình này là 1 phần của bài tập lớn môn học Mật mã ứng dụng trong an toàn thông tin, trường Học viện Kỹ thuật Mật Mã khoá AT14, đề tài "Mật mã đường cong"

<!-- GETTING STARTED -->
## Sử dụng

Để thực hiện chương trình, clone repo này rồi compile chương trình hoặc sử dụng các file binary trong phần Releases.

### Yêu cầu

Để compile chương trình cần các thành phần sau đây:
* Thư viện MbedTLS 2.27.0: https://github.com/ARMmbed/mbedtls/releases/tag/v2.27.0
* Các chương trình liên quan tới compile: gcc, mingw, clang, v.v


### Compile chương trình (Linux)

1. Tải source code của thư viện MbedTLS 2.27.0 về và compile theo hướng dẫn trên trang chủ:
https://tls.mbed.org/kb/compiling-and-building/how-do-i-build-compile-mbedtls

2. Compile chương trình với lệnh sau:
* Client:
```sh 
gcc -I/path/to/mbed/mbedtls-2.27.0/include \
	-I/path/to/mbed/mbedtls-2.27.0/library \
	-g /path/to/client.c /path/to/mbed/mbedtls-2.27.0/library/*.c \
	-o client.elf
```

* Server:
```sh 
gcc -I/path/to/mbed/mbedtls-2.27.0/include \
	-I/path/to/mbed/mbedtls-2.27.0/library \
	-g /path/to/client.c /path/to/mbed/mbedtls-2.27.0/library/*.c \
	-o server.elf
```

3. Chạy chương trình trên 2 cửa số terminal riêng biệt:
```sh
./server.elf
```

```sh
./client.elf
```

### Compile chương trình (Windows x64)
1. Tải source code của thư viện MbedTLS 2.27.0 về và compile:
- MinGW-W64: https://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win32/Personal%20Builds/mingw-builds/installer/mingw-w64-install.exe
- Thêm đường dẫn chứa binary của MinGW vào PATH, đường dẫn này có dạng: `C:\path\to\mingw-64\mingw\bin`. Nếu làm theo bài viết bên dưới thì đường dẫn này là: `C:\mingw-64\mingw64\bin` 
- Hướng dẫn compile thư viện bằng MinGW-W64: https://tls.mbed.org/kb/compiling-and-building/compiling-mbedtls-in-mingw

2. Compile thư viện với các lệnh sau:
* Client: 
```sh
gcc -I C:\path\to\mbedtls-2.27.0\include\ -I C:\path\to\mbedtls-2.27.0\library\ -L C:\path\to\mbedtls-2.27.0\library\ -g .\client.c -std=gnu99 -lmbedtls -lmbedx509 -lmbedcrypto -lws2_32 -w -o client.exe
```

* Server:
```sh
gcc -I C:\path\to\mbedtls-2.27.0\include\ -I C:\path\to\mbedtls-2.27.0\library\ -L C:\path\to\mbedtls-2.27.0\library\ -g .\server.c -std=gnu99 -lmbedtls -lmbedx509 -lmbedcrypto -lws2_32 -w -o server.exe
```

3. Chạy chương trình trên 2 cửa số terminal riêng biệt:
```sh
./server.exe
```

```sh
./client.exe
```

* Video: https://www.youtube.com/watch?v=8D_XH5UM8lk
<!-- CONTACT -->
## Credits

Nhóm làm bài tập gồm các thành viên sau:

* Cơ sở lý thuyết:
1. Nguyễn Tùng Anh - AT140102(Nhóm trưởng)
2. Hoàng Nguyên Thái - AT140340
3. Ngô Nguyễn Quỳnh Hương - AT140815
4. Phạm Thành Trung Hiếu - AT140420
5. Nguyễn Thế Bắc - AT140103

* Viết chương trình:
1. Nguyễn Hữu Hoàng - AT140523
2. Đoàn Văn Quỳnh - AT130843
3. Đào Thành Đạt - AT140306
4. Nguyễn Văn Chung - AT140504
5. Nguyễn Thành Hiếu - AT140419

Địa chỉ repository: https://github.com/catmandx/ecc-btl
