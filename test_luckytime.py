"""Test unit và integration cho chức năng Lucky Time 0H."""

import json
import sqlite3
import tempfile
import time
from pathlib import Path
from datetime import datetime, timedelta

from master_server import (
    LocalStore,
    _ensure_lucky_tables,
    _lucky_target_date,
    _get_3_days_prior,
    _mask_email,
    _validate_shop_email,
    _get_active_lucky_winner,
    execute_lucky_draw,
    run_pending_lucky_draws,
    _master_tzinfo,
    configure_console_encoding,
    MASTER_TIMEZONE,
)


def test_email_validation():
    print("[1] Test email validation...")
    valid, res = _validate_shop_email("shop@gmail.com")
    assert valid is True
    assert res == "shop@gmail.com"

    valid, res = _validate_shop_email("  Shop_AOV.VIP+1@yahoo.com.vn  ")
    assert valid is True
    assert res == "shop_aov.vip+1@yahoo.com.vn"

    valid, res = _validate_shop_email("invalid-email")
    assert valid is False

    valid, res = _validate_shop_email("")
    assert valid is False
    print("  -> Email validation PASSED")


def test_email_masking():
    print("[2] Test email masking...")
    assert _mask_email("shoplienquan@gmail.com") == "sho***an@gmail.com"
    assert _mask_email("admin@test.com") == "ad***n@test.com"
    assert _mask_email("hi@a.vn") == "h***@a.vn"
    print("  -> Email masking PASSED")


def test_lucky_draw_logic_and_3_days_condition():
    print("[3] Test Lucky Draw & 3 Days Condition...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_file = Path(tmp_dir) / "test_master.db"
        store = LocalStore(db_file)
        _ensure_lucky_tables(store)

        tz = _master_tzinfo()
        base_date = datetime(2026, 4, 1, tzinfo=tz)

        # Ngày 1: 2026-04-01
        date_1 = "2026-04-01"
        # Đăng ký 15 email cho ngày 1
        for i in range(1, 16):
            email = f"shop{i:02d}@gmail.com"
            store.exec(
                "INSERT INTO lucky_registrations (email, target_date, created_at, status) VALUES (?, ?, ?, 'registered')",
                (email, date_1, time.time()),
            )

        # Quay thưởng ngày 1
        res_1 = execute_lucky_draw(store, date_1)
        assert res_1["ok"] is True
        assert res_1["total_registered"] == 15
        assert res_1["eligible_count"] == 15
        assert res_1["winner_count"] == 10
        assert len(res_1["winners"]) == 10

        day_1_winners = set(res_1["winners"])
        print(f"  -> Ngày 1: 10 winners được chọn: {day_1_winners}")

        # Kiểm tra bảng lucky_winners ngày 1
        win_rows = store.fetch("SELECT email, valid_from, valid_until FROM lucky_winners WHERE draw_date=?", (date_1,))
        assert len(win_rows) == 10

        # Ngày 2: 2026-04-02 (Cách 1 ngày)
        # Giả sử tất cả 15 shop hôm trước lại đăng ký tiếp cho ngày 2, cộng thêm 5 shop mới (shop16 -> shop20)
        date_2 = "2026-04-02"
        for i in range(1, 21):
            email = f"shop{i:02d}@gmail.com"
            store.exec(
                "INSERT INTO lucky_registrations (email, target_date, created_at, status) VALUES (?, ?, ?, 'registered')",
                (email, date_2, time.time()),
            )

        # Quay thưởng ngày 2
        res_2 = execute_lucky_draw(store, date_2)
        assert res_2["ok"] is True
        assert res_2["total_registered"] == 20
        # 10 shop đã trúng ở ngày 1 (3 ngày gần nhất) PHẢI BỊ LOẠI KHỎI DANH SÁCH XÉT TRÚNG!
        assert res_2["eligible_count"] == 10
        # Kiểm tra không có bất kỳ winner nào của ngày 1 lọt vào danh sách winner ngày 2
        day_2_winners = set(res_2["winners"])
        assert day_1_winners.isdisjoint(day_2_winners), "Winner ngày 1 không được trúng vào ngày 2!"
        print(f"  -> Ngày 2: Điều kiện 3 ngày đã loại chính xác 10 winner ngày 1! Winners ngày 2: {day_2_winners}")

        # Ngày 3: 2026-04-03 (Cách 2 ngày so với ngày 1, cách 1 ngày so với ngày 2)
        date_3 = "2026-04-03"
        # Đăng ký lại
        for i in range(1, 21):
            email = f"shop{i:02d}@gmail.com"
            store.exec(
                "INSERT INTO lucky_registrations (email, target_date, created_at, status) VALUES (?, ?, ?, 'registered')",
                (email, date_3, time.time()),
            )
        res_3 = execute_lucky_draw(store, date_3)
        # Cả winner ngày 1 và ngày 2 đều nằm trong 3 ngày gần nhất (2026-04-02 và 2026-04-01)!
        # Vì cả 20 shop đều đã trúng ở ngày 1 hoặc ngày 2, nên không còn shop nào đủ điều kiện!
        assert res_3["eligible_count"] == 0
        assert res_3["winner_count"] == 0
        print("  -> Ngày 3: Cả 20 shop đều đã trúng trong 3 ngày gần nhất nên eligible_count = 0. PASSED")

        # Ngày 5: 2026-04-05 (Cách 4 ngày so với ngày 1 -> Các shop trúng ngày 1 ĐƯỢC PHÉP TRÚNG LẠI!)
        date_5 = "2026-04-05"
        # 3 ngày trước date_5 là: 2026-04-04, 2026-04-03, 2026-04-02.
        # Ngày 2026-04-01 đã nằm ngoài 3 ngày gần nhất!
        prior_days = _get_3_days_prior(date_5)
        assert prior_days == ["2026-04-04", "2026-04-03", "2026-04-02"]
        assert "2026-04-01" not in prior_days

        # Các shop ngày 1 đăng ký lại cho ngày 5
        for email in day_1_winners:
            store.exec(
                "INSERT INTO lucky_registrations (email, target_date, created_at, status) VALUES (?, ?, ?, 'registered')",
                (email, date_5, time.time()),
            )
        res_5 = execute_lucky_draw(store, date_5)
        assert res_5["eligible_count"] == 10
        assert res_5["winner_count"] == 10
        print(f"  -> Ngày 5 (sau 4 ngày): Các shop trúng ngày 1 đã đủ điều kiện trúng lại: {res_5['winners']}. PASSED")
        store._conn.close()


def test_free_slot_check_access():
    print("[4] Test Free Slot Check Access...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_file = Path(tmp_dir) / "test_master.db"
        store = LocalStore(db_file)
        _ensure_lucky_tables(store)

        email = "shoplucky@gmail.com"
        now = time.time()
        # Thêm 1 winner đang active (valid_from = now - 100, valid_until = now + 86400)
        store.exec(
            "INSERT INTO lucky_winners (draw_date, email, user_id, valid_from, valid_until, status, created_at) "
            "VALUES (?, ?, 123, ?, ?, 'active', ?)",
            ("2026-04-01", email, now - 100, now + 86400, now),
        )

        lucky = _get_active_lucky_winner(store, email)
        assert lucky is not None
        assert lucky["email"] == email
        assert lucky["valid_until"] > now

        # Email chưa trúng hoặc hết hạn
        expired_email = "shopexpired@gmail.com"
        store.exec(
            "INSERT INTO lucky_winners (draw_date, email, user_id, valid_from, valid_until, status, created_at) "
            "VALUES (?, ?, 124, ?, ?, 'active', ?)",
            ("2026-03-25", expired_email, now - 100000, now - 100, now - 100000),
        )
        assert _get_active_lucky_winner(store, expired_email) is None
        assert _get_active_lucky_winner(store, "unknown@gmail.com") is None
        print("  -> Free slot check access logic PASSED")
        store._conn.close()


if __name__ == "__main__":
    configure_console_encoding()
    test_email_validation()
    test_email_masking()
    test_lucky_draw_logic_and_3_days_condition()
    test_free_slot_check_access()
    print("\n==========================================")
    print("🎉 TẤT CẢ UNIT & INTEGRATION TESTS ĐỀU ĐẠT 100%!")
    print("==========================================")
