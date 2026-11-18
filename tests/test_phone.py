from vipii import analyze


def found(text, entity_type):
    return [e.text for e in analyze(text) if e.type == entity_type]


def test_detects_plain_mobile_number():
    assert found("Gọi tôi qua số 0912345678 nhé", "PHONE_NUMBER") == ["0912345678"]


def test_detects_mobile_with_separators_and_country_code():
    assert found("SĐT: 091.234.5678", "PHONE_NUMBER") == ["091.234.5678"]
    assert found("liên hệ +84 912 345 678", "PHONE_NUMBER") == ["+84 912 345 678"]
    assert found("hotline 0912-345-678.", "PHONE_NUMBER") == ["0912-345-678"]


def test_detects_landline():
    assert found("Văn phòng: 024 3825 1234", "PHONE_NUMBER") == ["024 3825 1234"]


def test_ignores_digits_inside_longer_numbers():
    assert found("mã đơn 109123456789012", "PHONE_NUMBER") == []


def test_ignores_invalid_mobile_prefix():
    # 01x and 04x/06x are not valid 10-digit mobile prefixes
    assert found("số 0612345678", "PHONE_NUMBER") == []
