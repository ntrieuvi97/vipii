"""Findings from the second independent review round."""
import subprocess
import sys
from pathlib import Path

import pytest

from vipii import Analyzer, analyze, anonymize, deanonymize, normalize

ROOT = Path(__file__).resolve().parents[1]


def types(text):
    return [(e.type, e.text) for e in analyze(text)]


@pytest.mark.parametrize("text,card", [
    ("Thẻ số 1 4111 1111 1111 1111", "4111 1111 1111 1111"),
    ("STT 1 4111111111111111", "4111111111111111"),
    ("Mã 25 4111-1111-1111-1111", "4111-1111-1111-1111"),
    ("12 28 4111 1111 1111 1111", "4111 1111 1111 1111"),
])
def test_card_after_a_short_digit_group(text, card):
    assert ("CREDIT_CARD", card) in types(text)
    assert card not in anonymize(text).text


@pytest.mark.parametrize("text,phone", [
    ("Em đã gửi ảnh CCCD rồi ạ. 0987654321", "0987654321"),
    ("Đã nhận CMND, chị gửi lại giúp em nhé: 0912 345 678", "0912 345 678"),
    ("Bản sao CCCD công chứng 2 bộ. Anh Hùng 0903123456", "0903123456"),
])
def test_anti_context_never_drops_a_phone(text, phone):
    assert ("PHONE_NUMBER", phone) in types(text)


def test_anti_context_still_breaks_ties():
    assert types("Mã số thuế 0300588568") == [("TAX_CODE", "0300588568")]
    assert types("STK 0912345678") == [("BANK_ACCOUNT", "0912345678")]


@pytest.mark.parametrize("text,name", [
    ("Nguyễn Văn An Giám Đốc", "Nguyễn Văn An"),
    ("Kính gửi Nguyễn Văn An Giám Đốc", "Nguyễn Văn An"),
    ("Trần Thị Bình Trưởng Phòng Kế Toán", "Trần Thị Bình"),
    ("Gửi Nguyễn Văn An Công Ty ABC", "Nguyễn Văn An"),
    ("Nguyễn Văn An Hà Nội", "Nguyễn Văn An"),
    ("Lê Văn Hùng Phó Giám Đốc Công Ty", "Lê Văn Hùng"),
    ("Nguyễn Thị Ngọc Bảo Trâm gọi", "Nguyễn Thị Ngọc Bảo Trâm"),
])
def test_name_followed_by_title_case_words_is_masked(text, name):
    assert name not in anonymize(text).text


@pytest.mark.parametrize("x", ["<\u00a0PERSON_1\u00a0>", "<PERSON_1\u2009>", "[\u00a0EMAIL_2]"])
def test_literal_round_trip_keeps_unicode_spaces(x):
    r = anonymize(f"ghi chú {x} cho Nguyễn Văn An")
    assert deanonymize(r.text, r.mapping) == normalize(f"ghi chú {x} cho Nguyễn Văn An")


@pytest.mark.parametrize("text", ["0912\u200b345678", "0912\u00ad345678", "0912\u200d345\u200c678"])
def test_zero_width_and_soft_hyphen_do_not_hide_numbers(text):
    assert [t for t, _ in types(f"SĐT {text}")] == ["PHONE_NUMBER"]


def test_address_does_not_swallow_a_person_after_dash():
    r = anonymize("Giao 12 Lê Lợi, Q.1 - Ông Nguyễn Văn An")
    assert "12" not in r.text and "Q.1" not in r.text and "Nguyễn" not in r.text


def test_space_joined_address_components_are_admin_units_only():
    assert types("Địa chỉ: 12 Lê Lợi, Quận 1 bản Word") == [("ADDRESS", "12 Lê Lợi, Quận 1")]


def test_non_latin_labels_do_not_collide():
    a = Analyzer(custom_terms={"日本": ["Tokyo"], "中国": ["Beijing"]})
    r = anonymize("Tokyo Beijing", analyzer=a, operators={"日本": "redact"})
    assert "Tokyo" not in r.text and "Beijing" not in r.text
    assert r.text.strip() != ""  # Beijing was replaced, not redacted


def test_user_label_literal_does_not_hijack_internal_type():
    a = Analyzer(custom_terms={"literal": ["Falcon"]})
    r = anonymize("Falcon", analyzer=a, operators={"literal": "redact"})
    assert r.text == "" and [e.text for e in r.entities] == ["Falcon"]


def cli(*args, stdin=b""):
    return subprocess.run([sys.executable, "-m", "vipii", *args], input=stdin,
                          capture_output=True, cwd=ROOT)


def test_cli_clean_errors_for_bad_inputs(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_bytes(b"\xff\xfe\x00bad")
    cases = [
        ("analyze", str(tmp_path / "missing.txt")),
        ("analyze", str(bad)),
        ("analyze", "--terms", f"P={bad}"),
        ("anonymize", "--map", str(tmp_path / "no" / "dir" / "m.json")),
    ]
    for args in cases:
        p = cli(*args, stdin=b"SDT 0912345678")
        assert p.returncode == 2, args
        assert b"Traceback" not in p.stderr, args
