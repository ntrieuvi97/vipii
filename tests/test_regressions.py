"""Regressions found by running examples/quyet_dinh.txt."""
from vipii import analyze


def types(text):
    return [(e.type, e.text) for e in analyze(text)]


def test_unaccented_all_caps_name_on_bank_documents():
    assert types("chủ tài khoản TRAN QUOC BAO") == [("PERSON", "TRAN QUOC BAO")]


def test_unaccented_title_case_three_word_name():
    assert types("From: Nguyen Thi Lan") == [("PERSON", "Nguyen Thi Lan")]


def test_unaccented_place_is_still_not_a_person():
    assert types("office in Ho Chi Minh City") == []


def test_capitalized_honorific_at_sentence_start():
    assert types("Điều 3. Chị Ngọc phụ trách.") == [("PERSON", "Ngọc")]


def test_english_title_case_is_not_an_unaccented_name():
    assert types("Do Not Disturb sign") == []
    assert types("new Mac Book Pro") == []
    assert types("Thai Food Menu") == []


def test_places_starting_with_honorific_words():
    assert types("du học Anh Quốc") == []
    assert types("tỉnh Bà Rịa Vũng Tàu") == []
    assert types("số 5 phố Bà Triệu") != [("PERSON", "Triệu")]


def test_plate_at_end_of_sentence():
    assert types("Xe công tác 30G-456.78.") == [("LICENSE_PLATE", "30G-456.78")]


def test_context_does_not_bleed_across_neighbouring_numbers():
    text = "đt 0283 822 1234,\nMST 0300588569"
    assert types(text) == [("PHONE_NUMBER", "0283 822 1234"), ("TAX_CODE", "0300588569")]
    text = "SĐT 0912345678, MST 0300588569"
    assert types(text) == [("PHONE_NUMBER", "0912345678"), ("TAX_CODE", "0300588569")]
