# checkpass

Master gọi `GET /healthz` của mỗi vệ tinh trong danh sách đã lưu ở trang quản trị mỗi 2 phút. Vệ tinh thường và VVIP được quản lý bằng hai danh sách riêng (`satellite_targets`, `vvip_satellite_targets`), nên thay đổi danh sách không cần khởi động lại master. Service thường chạy `python service-litesel.py`; service VVIP chạy `python service-liteselVVIP.py` và chỉ claim hàng đợi VVIP.

Master trực tiếp đăng nhập tài khoản probe và kiểm tra API Kiện Tướng định kỳ, không phụ thuộc vệ tinh. HTTP 404 từ API Kiện Tướng hiển thị `Kiện tướng: đang sập` màu đỏ; phản hồi 2xx/3xx hiển thị `Kiện tướng: sẵn sàng` màu xanh. Lỗi mạng giữ trạng thái xác nhận gần nhất. Tài khoản probe mặc định có thể thay bằng `KIENTUONG_MONITOR_ACCOUNT`, `KIENTUONG_MONITOR_PASSWORD`; chu kỳ mặc định 120 giây có thể thay bằng `KIENTUONG_MONITOR_INTERVAL` (tối thiểu 30 giây).

Job VVIP chia chunk ưu tiên theo tỷ lệ 30% cho VPS VVIP, 70% cho VPS thường (phần VVIP làm tròn lên khi số chunk không chia hết cho 10). Khi hết chunk ưu tiên có thể nhận, VPS VVIP lấy tiếp chunk trống thuộc phần thường của job VVIP. Chunk đang được VPS khác xử lý chỉ được nhận lại khi hết lease; vệ tinh tiếp tục polling để nhận việc mới. VPS thường vẫn có thể hỗ trợ phần VVIP khi hết việc ưu tiên, còn VPS VVIP chỉ nhận job VVIP.

## SP1S SSO và thanh toán Checkban

Người dùng Checkpass đăng nhập bằng tài khoản SP1S; license key cũ không còn được chấp nhận khi tích hợp SP1S được cấu hình. `MASTER_TOKEN` chỉ dành cho quản trị và vệ tinh.

Biến môi trường bắt buộc trên master:

- `AOVSHOP_API_URL`: URL backend AOVshop, không có `/api` ở cuối.
- `CHECKPASS_SERVICE_TOKEN`: chuỗi bí mật giống hệt backend AOVshop.
- `SP1S_FRONTEND_URL`: mặc định `https://sp1s.shop`.
- `CHECKPASS_PUBLIC_URL`: URL public của master, ví dụ `https://check.sp1s.shop`.

Backend AOVshop cần `CHECKPASS_SERVICE_TOKEN`, `CHECKPASS_ALLOWED_ORIGINS` và `CHECKPASS_URL`. Vệ tinh thường và VVIP dùng chung toàn bộ env, bao gồm `MASTER_TOKEN`; loại service chỉ được xác định bằng entrypoint và endpoint claim. Nên deploy backend trước để migration bổ sung cột tiền chính xác và các bảng SSO/billing chạy xong, sau đó deploy frontend SP1S, cuối cùng mới deploy master.

Tiền được lưu chính xác theo đơn vị 0,1 VND (`balance_tenths`). Chế độ số lượng tạm giữ `số tài khoản × 0,3đ`, sau đó quyết toán `số đúng pass × 0,3đ + số Không thể log × 0,1đ`. Đúng pass gồm Đủ LV, Chưa đạt, Bị khóa và CTNV; Chưa thể check không tính phí. Chế độ thời gian thường có giá `5.000đ / 30 phút`; VVIP có hàng đợi và entitlement riêng với giá `10.000đ / 30 phút`.

Khuyến mãi nạp tiền được cấu hình tại trang quản trị AOVShop bằng ba khóa `checkpass_deposit_bonus_enabled`, `checkpass_deposit_bonus_minimum_amount` và `checkpass_deposit_bonus_percent`. Mỗi đơn chốt số thưởng lúc tạo; khi thanh toán thành công, tiền gốc vào ví shop và tiền thưởng vào `checkpass_bonus_tenths`. Checkpass ưu tiên trừ tiền thưởng, trong khi đơn mua sản phẩm thường chỉ được trừ `balance_tenths`.
