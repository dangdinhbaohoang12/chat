# LAN Chat Full

Tính năng:
- Đăng ký / đăng nhập / đăng xuất
- bcrypt mã hóa mật khẩu
- Avatar người dùng
- Đổi mật khẩu
- Chat phòng
- Chat riêng
- Emoji
- Thông báo đang nhập
- Chỉnh sửa tin nhắn
- Thu hồi tin nhắn
- Trả lời tin nhắn
- Tìm kiếm tin nhắn
- Ghim tin nhắn
- Kéo thả file
- Gửi nhiều file cùng lúc
- Gửi thư mục
- Upload ảnh
- Preview ảnh
- Tải file bằng nút Download
- Thanh tiến trình upload
- Phòng công khai / có mật khẩu / ẩn / ẩn + mật khẩu
- Người tạo phòng là trưởng nhóm
- Phó nhóm do trưởng nhóm chỉ định
- Mời thành viên
- Kick thành viên
- Duyệt thành viên
- Chuyển quyền trưởng nhóm
- Đổi tên phòng
- Đổi mật khẩu phòng
- Ẩn / hiện phòng
- Bật / tắt duyệt thành viên
- Xóa nhóm
- Thành viên có thể chat, gửi file, gửi thư mục, emoji, tải file

## Cài đặt
```bash
npm install
npm start
```

## Truy cập
http://IP_MAY_CHU:3000

- Phó nhóm là tùy chọn, không bắt buộc phải có.
- Phó nhóm có quyền mời, kick thành viên thường, duyệt, ghim và quản lý file.

- Trưởng nhóm có thể chỉ định hoặc thu hồi phó nhóm.
- Phó nhóm chỉ kick thành viên thường; không kick được trưởng nhóm.


Bản vá: sửa sự kiện nút trong danh sách thành viên để kick/chỉ định phó hoạt động đúng.
