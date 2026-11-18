from vipii import analyze


def types(text):
    return [(e.type, e.text) for e in analyze(text)]


# --- Bank cards (Luhn) and accounts (context-required)

def test_detects_napas_card_with_luhn():
    text = "Thẻ 9704 3612 3456 7895 hết hạn 12/27"
    assert types(text) == [("CREDIT_CARD", "9704 3612 3456 7895")]


def test_detects_visa_card_with_dashes():
    assert types("card 4111-1111-1111-1111") == [("CREDIT_CARD", "4111-1111-1111-1111")]


def test_rejects_card_failing_luhn():
    assert types("Thẻ 9704 3612 3456 7891") == []


def test_bank_account_with_context():
    assert types("STK 0011004123456 Vietcombank") == [("BANK_ACCOUNT", "0011004123456")]
    assert types("chuyển vào tài khoản số 19036789012345 Techcombank") == [
        ("BANK_ACCOUNT", "19036789012345")
    ]


def test_bank_account_context_beats_cccd_shape():
    assert types("STK: 001090123456") == [("BANK_ACCOUNT", "001090123456")]


def test_bank_account_needs_context():
    assert types("mã vận đơn 0011004123456") == []


# --- Email

def test_detects_email():
    assert types("email: nguyen.van.a@congty.example.vn") == [("EMAIL", "nguyen.van.a@congty.example.vn")]


# --- License plates

def test_detects_car_plates():
    assert types("xe biển số 30A-123.45") == [("LICENSE_PLATE", "30A-123.45")]
    assert types("ô tô 51F-12345 đỗ trước cổng") == [("LICENSE_PLATE", "51F-12345")]


def test_detects_motorbike_plates():
    assert types("BKS 29-B1 123.45") == [("LICENSE_PLATE", "29-B1 123.45")]
    assert types("xe máy 59X1-123.45") == [("LICENSE_PLATE", "59X1-123.45")]


# --- Passport, date of birth, social insurance (all context-required)

def test_passport_requires_context():
    assert types("Hộ chiếu số C1234567") == [("PASSPORT", "C1234567")]
    assert types("mã sản phẩm C1234567") == []


def test_date_of_birth_requires_birth_context():
    assert types("sinh ngày 12/05/1990 tại Huế") == [("DATE_OF_BIRTH", "12/05/1990")]
    assert types("họp ngày 12/05/2024") == []


def test_social_insurance_number():
    assert types("Mã số BHXH: 0123456789") == [("SOCIAL_INSURANCE", "0123456789")]
