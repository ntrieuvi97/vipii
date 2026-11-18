from vipii import analyze


def types(text):
    return [(e.type, e.text) for e in analyze(text)]


# --- CCCD (12 digits: 3-digit province code + century/gender digit + yy + 6 digits)

def test_detects_cccd_with_context():
    assert types("Số CCCD: 001090123456") == [("NATIONAL_ID", "001090123456")]


def test_detects_valid_cccd_without_context():
    assert types("001090123456 cấp tại Hà Nội") == [("NATIONAL_ID", "001090123456")]


def test_rejects_cccd_with_unknown_province_code():
    assert types("mã 003090123456") == []


def test_cmnd_9_digits_requires_context():
    assert types("CMND số 123456789") == [("NATIONAL_ID", "123456789")]
    assert types("mã hàng 123456789") == []


# --- Mã số thuế (10 digits, check digit; optional -XXX branch suffix)

def test_detects_tax_code_with_valid_checksum_and_context():
    assert types("MST: 0101248141") == [("TAX_CODE", "0101248141")]


def test_tax_code_beats_phone_when_context_says_tax():
    # 0300588569 also looks like a mobile number (03x)
    assert types("Mã số thuế 0300588569") == [("TAX_CODE", "0300588569")]


def test_detects_branch_tax_code():
    assert types("MST chi nhánh: 0300588569-001") == [("TAX_CODE", "0300588569-001")]


def test_tax_code_needs_context():
    assert types("đơn hàng 0101248141") == []
