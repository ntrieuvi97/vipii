from vipii import analyze


def persons(text):
    return [e.text for e in analyze(text) if e.type == "PERSON"]


def test_full_name_with_common_surname():
    assert persons("Khách hàng Nguyễn Văn An đã ký hợp đồng") == ["Nguyễn Văn An"]


def test_two_word_name():
    assert persons("người nhận: Lê Hoa") == ["Lê Hoa"]


def test_single_letter_given_name():
    assert persons("ký bởi Nguyễn Văn A.") == ["Nguyễn Văn A"]


def test_honorific_without_known_surname():
    assert persons("chị Lan gọi lại sau") == ["Lan"]
    assert persons("Gửi anh Tuấn Anh, ") == ["Tuấn Anh"]


def test_sentence_initial_word_is_not_part_of_name():
    assert persons("Gửi Trần Minh Tuấn") == ["Trần Minh Tuấn"]


def test_all_caps_name_in_forms():
    assert persons("Họ tên: NGUYỄN THỊ MAI") == ["NGUYỄN THỊ MAI"]


def test_two_names_in_one_sentence():
    assert persons("Bà Phạm Thu Hà và ông Đỗ Quang Huy") == ["Phạm Thu Hà", "Đỗ Quang Huy"]


def test_nfd_input_is_normalized():
    import unicodedata

    text = unicodedata.normalize("NFD", "Khách hàng Nguyễn Văn An")
    assert persons(text) == ["Nguyễn Văn An"]


# --- false positives we must avoid

def test_provinces_are_not_people():
    assert persons("Văn phòng tại Hà Nội và Cao Bằng") == []
    assert persons("chi nhánh TP Hồ Chí Minh") == []


def test_streets_named_after_people_are_not_people():
    assert persons("số 12 đường Lê Lợi") == []
    assert persons("phố Trần Hưng Đạo") == []


def test_common_words_after_surname_are_not_names():
    assert persons("Phạm vi dự án") == []
    assert persons("Mai tôi đi công tác") == []
    assert persons("Anh ấy nói vậy") == []
