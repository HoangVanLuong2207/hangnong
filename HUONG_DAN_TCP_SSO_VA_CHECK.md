# TCP Login, SSO Key và luồng check nhiều tài khoản

Tài liệu này mô tả luồng đang dùng để kiểm tra các tài khoản do người vận hành sở hữu hoặc được ủy quyền kiểm tra. Mục tiêu là tách rõ dữ liệu bí mật của phiên, kết quả được lưu và log kỹ thuật.

## 1. Chuỗi xử lý của một tài khoản

```text
user|pass
  -> TCP LOGIN_PREPARE (0x100)
  -> TCP LOGIN (0x101)
  -> UID + TCP session_key
  -> TCP SSO_KEY_GET (0x1BA)
  -> sso_key + expiry_time
  -> OAuth/Web session của từng service
  -> API chỉ đọc: Kiện Tướng, rồi Sale/Skin (nếu được tích hợp)
  -> report kết quả public
  -> hủy dữ liệu phiên bí mật
```

`LOGIN_PREPARE` nhận dữ liệu chuẩn bị (salt/verify code) để tạo payload login và chưa gửi dữ liệu mật khẩu. Nếu TCP từ chối tại bước này, hệ thống kiểm tra lại; cùng mã từ chối qua hai lần liên tiếp thì ghi `FAIL / Không thể log` vì tài khoản không thể đi tiếp tới bước mật khẩu.

Khi server từ chối tại `LOGIN_PREPARE` hoặc `LOGIN`, hệ thống kiểm tra lại. Chỉ khi cùng bước và cùng mã từ chối xuất hiện liên tiếp hai lần mới ghi `FAIL / Không thể log`. `LOGIN_PREPARE` chưa kiểm tra mật khẩu nên nhãn này chỉ khẳng định tài khoản không thể tiếp tục đăng nhập; nó không tự khẳng định riêng nguyên nhân sai mật khẩu. Login thành công trả về UID và `session_key` TCP dài 16 byte.

## 2. SSO_KEY_GET

Sau TCP login thành công, client gọi `SSO_KEY_GET` (`0x1BA`):

```python
with GarenaTcpClient(timeout=20) as client:
    uid = client.login(account, password)
    sso = client.get_sso_key()

# sso.uid
# sso.sso_key       # chỉ tồn tại trong RAM
# sso.expiry_time   # Unix timestamp
```

Lệnh này cần UID và `session_key` của đúng phiên TCP vừa login. Request không có payload nghiệp vụ, nhưng được bảo vệ bằng `session_key`; response phải có `sso_key` hex 64 ký tự và `expiry_time` còn hiệu lực.

Không dùng TCP `session_key` như cookie web. `sso_key` chỉ là đầu vào cho luồng SSO/OAuth tiếp theo. Cookie và token của WebSession cũng chỉ được dùng cho đúng account và đúng service.

## 3. Check song song

Mỗi account luôn có phiên độc lập:

```text
Account A -> TCP client A -> session_key A -> sso_key A -> WebSession A
Account B -> TCP client B -> session_key B -> sso_key B -> WebSession B
Account C -> TCP client C -> session_key C -> sso_key C -> WebSession C
```

Không dùng lại `session_key`, `sso_key`, cookie hoặc OAuth token giữa các account.

`WORKERS` là số account có thể được xử lý đồng thời. `START_GAP` là khoảng cách tối thiểu giữa **thời điểm bắt đầu TCP LOGIN** trên toàn worker, nhằm giảm nguy cơ bị rate limit. Vì vậy `WORKERS=8`, `START_GAP=3` vẫn có tối đa 8 luồng đang xử lý, nhưng không bắt đầu tám lần login cùng lúc.

Sau khi login, mỗi worker có thể gọi các API chỉ đọc của account đó trong khi worker khác xử lý account khác.

## 4. Dữ liệu giữ trong RAM và dữ liệu được lưu

Chỉ giữ trong RAM đến khi account kết thúc:

```python
runtime_auth = {
    "uid": uid,
    "tcp_session_key": client.session_key,
    "sso_key": sso.sso_key,
    "sso_expiry": sso.expiry_time,
    "web_session": session,
}
```

Không đưa `runtime_auth` vào `row_json`, database kết quả, CSV/XLSX, API response hoặc log.

Kết quả có thể lưu lâu chỉ gồm dữ liệu public cần cho UI/export, ví dụ:

```json
{
  "uid": "123456",
  "tcp_status": "OK",
  "kientuong_status": "OK",
  "name": "Tên nhân vật",
  "level": 35,
  "skin_status": "OK",
  "skin_count": 84,
  "skin_unmapped_count": 3,
  "checked_at": "2026-09-08T00:00:00+07:00"
}
```

Khi xong hoặc có lỗi, xóa password khỏi object credential, đóng TCP client và bỏ tham chiếu đến SSO key/cookie. Nếu worker chết giữa chừng, chạy lại từ login; không lưu session hoặc SSO key để resume.

## 5. Kết quả và retry

- `OK`: lấy được dữ liệu Kiện Tướng đủ để kết luận (level hoặc CTNV đã xác nhận).
- `FAIL / Không thể log`: khi TCP `LOGIN_PREPARE` hoặc `LOGIN` bị từ chối cùng bước và cùng mã qua hai lần liên tiếp; không khẳng định riêng nguyên nhân sai mật khẩu.
- `CHƯA THỂ CHECK`: timeout, lỗi mạng, rate limit, CAPTCHA/OAuth hoặc dữ liệu chưa đủ. Không đánh đồng với sai mật khẩu.

Một kết quả skin lỗi không được làm hỏng kết quả Kiện Tướng đã thành công. Ví dụ: `kientuong_status=OK`, `skin_status=CHƯA THỂ CHECK`.

## 6. Log an toàn

Log chỉ ghi stage, trạng thái, thời gian và số liệu tổng hợp:

```text
[check] account=abc***89 stage=tcp_login ok=true uid=123456 elapsed_ms=820
[check] account=abc***89 stage=sso_key ok=true expires_in_s=1800 elapsed_ms=130
[check] account=abc***89 stage=kientuong ok=true level=35 elapsed_ms=410
[check] account=abc***89 stage=sale_inventory ok=true owned_items=120 matched_skins=84 unmapped=3 elapsed_ms=530
```

Tuyệt đối không log password, password hash, TCP `session_key`, `sso_key`, OAuth token/code, cookie, Authorization header, raw response API hoặc danh sách inventory đầy đủ. Không in một phần `MASTER_TOKEN` vào log: ngay cả token bị che một phần cũng không cần thiết cho vận hành.

## 7. Phần check skin

Check skin là pha bổ sung sau Kiện Tướng:

```text
SSO/OAuth Sale -> API inventory/getUser -> item ID sở hữu
-> lọc item skin -> map qua skins.json -> tổng hợp số skin
```

`skins.json`/`skin.py` chỉ là catalog map ID sang tên skin. Trước khi đưa vào worker, cần xác minh bằng một account được ủy quyền rằng endpoint Sale hiện tại thực sự trả inventory/owned items; catalog Sale có thể không phản ánh toàn bộ skin lịch sử.
