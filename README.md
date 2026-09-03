# CMS Quản trị khóa — nguyên mẫu trực quan

Nguyên mẫu **chỉ để demo và làm rõ nghiệp vụ**. Không phải sản phẩm.

- Không kết nối OpenBao hay bất kỳ hệ thống nào
- **Toàn bộ dữ liệu là giả lập** — tên đối tượng, mã khóa, hồ sơ đều bịa ra
- Mọi thao tác chỉ đổi state trong bộ nhớ trình duyệt, F5 là reset
- Không có backend, không có API, không lưu gì

## Xem trực tiếp

👉 https://khoileee.github.io/cmskey/

Hoặc tải về, giải nén rồi **nháy đúp `index.html`** — chạy được ngay, không cần cài gì.

## Bối cảnh

Công cụ dự kiến đặt trên nền **OpenBao** (bản mã nguồn mở tách từ HashiCorp Vault).
OpenBao lo phần lõi bảo mật — sinh khóa, cất khóa, xoay khóa, thu hồi.
Nguyên mẫu này phác họa **lớp nghiệp vụ** mà OpenBao không có:

1. **Sổ hồ sơ khóa** — khóa nào cấp cho ai, theo hồ sơ nào, hết hạn khi nào
2. **Tạm khóa** — trạng thái tạm dừng có thể khôi phục
3. **Nhật ký & báo cáo** — phục vụ kiểm toán

## Cách xem

| Màn | Nội dung |
|---|---|
| Danh mục khóa | Toàn bộ nghiệp vụ nằm trên một danh sách |
| Danh mục đối tượng | Khai báo đối tượng được cấp khóa |
| Nhật ký & báo cáo | Đầu ra cho kiểm toán |

Bấm vào biểu tượng **(i)** cạnh mỗi trường / tiêu đề cột / nút bấm để xem giải thích:
trường đó là gì, chọn nó thì trường nào đổi theo, và JSON gửi xuống OpenBao trông ra sao.

Bật/tắt **"Hiện ghi chú nghiệp vụ"** ở thanh breadcrumb để hiện các điểm còn chờ chốt.

## Chạy bằng máy chủ tĩnh (tuỳ chọn)

Không bắt buộc — mở `index.html` là đủ. Nếu muốn chạy qua HTTP:

```bash
node server.js      # → http://localhost:4300
```

Hoặc nháy đúp `start.bat` trên Windows.

## Cấu trúc

```
index.html   khung layout
app.css      giao diện
app.js       dữ liệu giả lập + toàn bộ màn hình và hộp thoại
server.js    máy chủ tĩnh tối giản, không cần npm install
vendor/      Bootstrap 4 + Font Awesome (thư viện nguồn mở, để chạy offline)
full/        bản phác thảo đầu tiên 7 menu — giữ lại để đối chiếu
```

## Ghi chú

Giao diện mô phỏng theo khuôn của một ứng dụng quản trị nội bộ để người xem dễ hình dung.
Thư mục `vendor/` chỉ chứa **thư viện nguồn mở của bên thứ ba** (Bootstrap, Font Awesome).
Không có mã nguồn hay tài sản của bất kỳ hệ thống nội bộ nào trong repo này.
