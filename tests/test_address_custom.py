from vipii import Analyzer, analyze


def types(text):
    return [(e.type, e.text) for e in analyze(text)]


# --- Addresses

def test_full_address_with_keywords():
    text = "Địa chỉ: số 12 đường Lê Lợi, phường Bến Nghé, quận 1, TP Hồ Chí Minh"
    expected = "số 12 đường Lê Lợi, phường Bến Nghé, quận 1, TP Hồ Chí Minh"
    assert types(text) == [("ADDRESS", expected)]


def test_address_with_abbreviations():
    text = "trú tại 45/3 Nguyễn Trãi, P.7, Q.5, TP.HCM"
    assert types(text) == [("ADDRESS", "45/3 Nguyễn Trãi, P.7, Q.5, TP.HCM")]


def test_rural_address_ending_with_bare_province():
    text = "Quê quán: thôn Đông, xã Tân Lập, huyện Đan Phượng, Hà Nội."
    assert types(text) == [("ADDRESS", "thôn Đông, xã Tân Lập, huyện Đan Phượng, Hà Nội")]


def test_alley_address():
    text = "giao hàng đến ngõ 15 Duy Tân, Cầu Giấy"
    assert types(text) == [("ADDRESS", "ngõ 15 Duy Tân, Cầu Giấy")]


def test_lone_district_is_not_an_address():
    assert types("quận 1 có nhiều quán cà phê") == []


def test_address_stops_before_lowercase_text():
    text = "Văn phòng ở phường Bến Nghé, quận 1, ngày 5 tháng 3 họp"
    assert types(text) == [("ADDRESS", "phường Bến Nghé, quận 1")]


# --- Custom business-secret terms

def test_custom_terms_are_detected_case_insensitively():
    a = Analyzer(custom_terms={"PROJECT": ["Phượng Hoàng", "Falcon"]})
    got = [(e.type, e.text) for e in a.analyze("Dự án Phượng Hoàng và FALCON ra mắt Q3")]
    assert got == [("PROJECT", "Phượng Hoàng"), ("PROJECT", "FALCON")]


def test_custom_terms_match_whole_words_only():
    a = Analyzer(custom_terms={"PROJECT": ["Falcon"]})
    assert a.analyze("Falconry là môn săn chim") == []
