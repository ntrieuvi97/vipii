"""Findings from the independent pre-release review (one test per reproducer)."""
import subprocess
import sys
import time
from pathlib import Path

import pytest

from vipii import Analyzer, PatternRecognizer, analyze, anonymize, deanonymize, normalize
from vipii.validators import luhn_ok

ROOT = Path(__file__).resolve().parents[1]


def types(text):
    return [(e.type, e.text) for e in analyze(text)]


def persons(text):
    return [e.text for e in analyze(text) if e.type == "PERSON"]


# ---------------------------------------------------------------- security

@pytest.mark.parametrize("text,etype,fragments", [
    ("Địa chỉ: số 8 ngõ 42 Hoàng Quốc Việt, phường Nghĩa Đô, Hà Nội", "ADDRESS",
     ["Hoàng", "Nghĩa", "42", "Hà Nội"]),
    ("Email: nguyenvana1990@mail.example", "EMAIL", ["nguyenvana", "gmail", "1990"]),
    ("biển số 30G-456.78", "LICENSE_PLATE", ["30G", "456", ".78"]),
    ("Khách hàng Nguyễn Văn An", "PERSON", ["Nguyễn", "Văn", " An"]),
    ("CMND số 1234", "NATIONAL_ID", []),
])
def test_mask_never_returns_original_fragments(text, etype, fragments):
    out = anonymize(text, operators={etype: "mask"}).text
    for frag in fragments:
        assert frag not in out


def test_mask_keeps_last_four_only_for_long_numeric_ids():
    assert anonymize("SĐT 0912345678", operators={"PHONE_NUMBER": "mask"}).text == \
        "SĐT ******5678"


EVIL = ["1/" * 20000, "1/1/1990/" * 5000, "A " * 20000, "1 " * 20000, "1-" * 20000,
        "a@" * 20000, "a." * 20000 + "@", "Phường " * 5000, "số 1 " * 5000, "9704 " * 5000,
        "0" * 50000, ("Nguyễn " * 3 + ", ") * 3000, "12A/" * 10000, "P." * 20000,
        "<" + "a_1" * 20000, "[A_1 " * 20000]


@pytest.mark.parametrize("evil", EVIL, ids=range(len(EVIL)))
def test_no_catastrophic_backtracking(evil):
    start = time.perf_counter()
    analyze(evil)
    assert time.perf_counter() - start < 2.0


def test_placeholder_like_input_survives_round_trip_and_is_hidden():
    x = "Khách hàng Nguyễn Văn An. Mẫu thư: Kính gửi [PERSON_1], SĐT <PHONE_NUMBER_1>."
    r = anonymize(x)
    assert "[PERSON_1]" not in r.text and "<PHONE_NUMBER_1>" not in r.text
    assert deanonymize(r.text, r.mapping) == normalize(x)


def test_shared_map_does_not_leak_values_through_quoted_placeholders():
    first = anonymize("SĐT 0912345678")
    doc = anonymize("Tài liệu mẫu ghi <PHONE_NUMBER_1>", mapping=first.mapping)
    assert "<PHONE_NUMBER_1>" not in doc.text
    assert deanonymize(doc.text, doc.mapping) == "Tài liệu mẫu ghi <PHONE_NUMBER_1>"


def test_hash_without_salt_warns_and_is_longer():
    with pytest.warns(UserWarning, match="salt"):
        out = anonymize("SĐT 0912345678", operators={"PHONE_NUMBER": "hash"}).text
    assert len(out.split(":")[-1].rstrip(">")) >= 16


# ---------------------------------------------------------------- logic

def test_card_followed_by_expiry_date():
    assert types("Thẻ Visa 4111-1111-1111-1111 03/27") == [
        ("CREDIT_CARD", "4111-1111-1111-1111")]
    assert types("Thẻ 4111111111111111 12/28") == [("CREDIT_CARD", "4111111111111111")]


def test_19_digit_visa():
    base = "411111111111111111"
    card = next(base + d for d in "0123456789" if luhn_ok(base + d))
    assert types(f"Thẻ visa: {card}") == [("CREDIT_CARD", card)]


@pytest.mark.parametrize("reply", ["tk <BAN\u212a_ACCOUNT_1>", "<EMA\u0130L_1>"])
def test_deanonymize_never_crashes_on_unicode_casefold_lookalikes(reply):
    mapping = {"<BANK_ACCOUNT_1>": "0071000123456", "<EMAIL_1>": "a@b.example"}
    assert deanonymize(reply, mapping) == reply


def test_vietnamese_custom_labels_are_transliterated():
    a = Analyzer(custom_terms={"Dự án": ["Falcon"], "Khách hàng": ["Vingroup"]})
    assert anonymize("Falcon cho Vingroup", analyzer=a).text == "<DU_AN_1> cho <KHACH_HANG_1>"


def test_operators_accept_raw_custom_labels():
    a = Analyzer(custom_terms={"Dự án": ["Falcon"]})
    assert anonymize("dự án Falcon", analyzer=a, operators={"Dự án": "redact"}).text == "dự án "


def test_custom_entity_types_are_sanitized_in_placeholders():
    a = Analyzer(recognizers=[PatternRecognizer("my>type", [(r"X\d", 0.9)])])
    res = anonymize("X1", analyzer=a)
    assert res.text == "<MY_TYPE_1>"
    assert deanonymize(res.text, res.mapping) == "X1"


def cli(*args, stdin=b""):
    return subprocess.run([sys.executable, "-m", "vipii", *args], input=stdin,
                          capture_output=True, cwd=ROOT)


def test_cli_op_applies_to_custom_label(tmp_path):
    terms = tmp_path / "s.txt"
    terms.write_text("Falcon\n", encoding="utf-8")
    p = cli("anonymize", "--terms", f"project-x={terms}", "--op", "project-x=mask",
            "--map", str(tmp_path / "m.json"), stdin="Làm Falcon".encode())
    assert p.stdout.decode() == "Làm ******"


def test_cli_deanonymize_fails_on_missing_map(tmp_path):
    p = cli("deanonymize", "--map", str(tmp_path / "typo.json"), stdin=b"<PERSON_1>")
    assert p.returncode != 0 and b"Traceback" not in p.stderr


def test_cli_bad_terms_spec_is_a_clean_error(tmp_path):
    p = cli("anonymize", "--terms", "foo", "--map", str(tmp_path / "m.json"), stdin=b"x")
    assert p.returncode == 2 and b"Traceback" not in p.stderr


def test_cli_rejects_corrupt_mapping(tmp_path):
    m = tmp_path / "m.json"
    m.write_text('{"<PERSON_1>": 5}', encoding="utf-8")
    p = cli("deanonymize", "--map", str(m), stdin=b"<PERSON_1>")
    assert p.returncode != 0 and b"Traceback" not in p.stderr


# ---------------------------------------------------------------- recall / precision

def test_nbsp_is_treated_as_space_and_preserved():
    text = "Họ tên: Nguyễn\u00a0Văn\u00a0An, SĐT 0912\u00a0345\u00a0678"
    assert types(text) == [("PERSON", "Nguyễn\u00a0Văn\u00a0An"),
                           ("PHONE_NUMBER", "0912\u00a0345\u00a0678")]
    r = anonymize(text)
    assert deanonymize(r.text, r.mapping) == text


@pytest.mark.parametrize("text,value", [
    ("Văn phòng (028) 3822 1234", "(028) 3822 1234"),
    ("Zalo (+84) 912 345 678", "(+84) 912 345 678"),
    ("gọi 84912345678", "84912345678"),
])
def test_more_phone_formats(text, value):
    assert types(text) == [("PHONE_NUMBER", value)]


@pytest.mark.parametrize("text,value", [
    ("Số CCCD 079 190 001 234", "079 190 001 234"),
    ("CMND: 025 123 456", "025 123 456"),
    ("CCCD: 099123456789", "099123456789"),
])
def test_grouped_and_context_backed_ids(text, value):
    assert types(text) == [("NATIONAL_ID", value)]


@pytest.mark.parametrize("text,names", [
    ("Họ tên: Tôn Nữ Thị Minh Châu", ["Tôn Nữ Thị Minh Châu"]),
    ("Ông Nguyễn Hoàng Phương Bảo Anh", ["Nguyễn Hoàng Phương Bảo Anh"]),
    ("Bà Công Tôn Nữ Thị Minh Hằng", ["Công Tôn Nữ Thị Minh Hằng"]),
    ("Danh sách: Nguyễn Văn An Trần Thị Bình", ["Nguyễn Văn An", "Trần Thị Bình"]),
    ("chu tai khoan: Le Van Tam", ["Le Van Tam"]),
    ("Do Van Ha gui bao cao", ["Do Van Ha"]),
])
def test_long_compound_and_unaccented_names(text, names):
    assert persons(text) == names


@pytest.mark.parametrize("text", ["STK1: 0071000123456", "Tài khoản số 2: 0071000123456"])
def test_label_with_index_digit_keeps_context(text):
    assert types(text) == [("BANK_ACCOUNT", "0071000123456")]


def test_address_with_undotted_abbreviations():
    assert types("giao 123 Lý Thường Kiệt P14 Q10") == [
        ("ADDRESS", "123 Lý Thường Kiệt P14 Q10")]


@pytest.mark.parametrize("text,value", [
    ("Sinh ngày 15 tháng 11 năm 1990", "15 tháng 11 năm 1990"),
    ("DOB: 1985-04-03", "1985-04-03"),
])
def test_more_dob_formats(text, value):
    assert types(text) == [("DATE_OF_BIRTH", value)]


@pytest.mark.parametrize("text", [
    "Gói cước 50GB 1000 phút", "Mua 12GB 2000 lần", "Model 30A 1234",
    "Trường Cao Đẳng Kinh Tế", "quần đảo Hoàng Sa", "Kết luận Hồ Sơ Vụ Án", "Mai Anh Đào nở",
])
def test_reported_false_positives(text):
    assert types(text) == []


def test_tax_context_beats_phone_shape_even_with_bad_checksum():
    assert types("Mã số thuế 0300588568") == [("TAX_CODE", "0300588568")]


def test_label_of_the_next_value_does_not_penalize_the_previous_one():
    assert types("0912345678, MST 0300588569") == [
        ("PHONE_NUMBER", "0912345678"), ("TAX_CODE", "0300588569")]
