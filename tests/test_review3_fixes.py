"""Findings from the third independent review round."""
import time

import pytest

from vipii import analyze, anonymize

CARD = "4111 1111 1111 1111"


def types(text):
    return [(e.type, e.text) for e in analyze(text)]


@pytest.mark.parametrize("text", [
    f"Thẻ {CARD} 15h", f"Thẻ {CARD} 5tr", f"Thẻ {CARD} 3DS",
    f"22 02 2026 {CARD}", f"STT 22 {CARD}", f"97046 54846 {CARD}",
    "Thẻ VISA-4111 1111 1111 1111", "ref-4111111111111111",
    "thẻ 4111  1111 1111 1111", "thẻ 4111.1111.1111.1111",
])
def test_no_card_digits_leak(text):
    out = anonymize(text).text
    assert "1111 1111" not in out and "11111111" not in out and "1111.1111" not in out
    assert "1111  1111" not in out


@pytest.mark.parametrize("text", [
    "SĐT 0987\u200b\u200b654321", "SĐT 0987\u200c\u200d654321", "SĐT 0987 \u200b654321",
    "SĐT 0987\u200e654321", "SĐT 0987\u202a654321\u202c", "SĐT 0987\u2066654321\u2069",
    "SĐT 0987\u2062654321", "SĐT 0987\u180e654321", "SĐT 0987\u034f654321",
])
def test_invisible_characters_cannot_hide_a_phone(text):
    out = anonymize(text).text
    assert "654321" not in out


def test_invisible_characters_cannot_hide_a_card_or_name():
    assert "1111 1111" not in anonymize("thẻ 4111\u200e1111 1111 1111").text.replace("\u200e", " ")
    assert "Văn" not in anonymize("Anh Nguyễn\u3164Văn An").text


@pytest.mark.parametrize("text,fragments", [
    ("Lê Thị Hồng Nhung Trưởng Ban Kiểm Soát", ["Nhung"]),
    ("Nguyễn Thị Ngọc Bảo Trâm Giám Đốc Công Ty", ["Bảo Trâm"]),
    ("Ký tên: Nguyễn Thị Ngọc Bảo Trâm Kế Toán Trưởng Công Ty", ["Bảo Trâm"]),
    ("Nguyễn Thị Minh Khai Phó Giám Đốc Điều Hành", ["Khai"]),
])
def test_long_name_before_long_title_is_fully_masked(text, fragments):
    out = anonymize(text).text
    for f in fragments:
        assert f not in out


@pytest.mark.parametrize("text,address", [
    ("Địa chỉ:\n7 Hàng Bạc", "7 Hàng Bạc"),
    ("Văn phòng: Tầng 5, 12 Hàng Bài", "12 Hàng Bài"),
    ("Địa chỉ (theo CCCD, cũ): 12 Hai Bà Trưng", "12 Hai Bà Trưng"),
    ("Số 12 Lê Lợi Phường 3 Quận 1", "Số 12 Lê Lợi Phường 3 Quận 1"),
    ("giao 12 Lê Lợi P.14 Q.10", "12 Lê Lợi P.14 Q.10"),
])
def test_address_label_on_previous_line_and_title_case_admin_units(text, address):
    assert ("ADDRESS", address) in types(text)


def test_address_context_still_does_not_bleed_into_the_next_component():
    assert types("Địa chỉ: 12 Lê Lợi, Quận 1 bản Word") == [("ADDRESS", "12 Lê Lợi, Quận 1")]


@pytest.mark.parametrize("evil", ["5 1 " * 250000, "2 7 " * 250000, "1 " * 500000])
def test_card_enumeration_worst_case_is_bounded(evil):
    start = time.perf_counter()
    analyze(evil)
    assert time.perf_counter() - start < 6.0
