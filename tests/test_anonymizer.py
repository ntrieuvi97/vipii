from vipii import anonymize, deanonymize, normalize

TEXT = "Anh Nguyễn Văn An, SĐT 0912345678, nhờ gọi lại cho Nguyễn Văn An"


def test_replace_uses_consistent_placeholders():
    res = anonymize(TEXT)
    assert res.text == "Anh <PERSON_1>, SĐT <PHONE_NUMBER_1>, nhờ gọi lại cho <PERSON_1>"
    assert res.mapping == {"<PERSON_1>": "Nguyễn Văn An", "<PHONE_NUMBER_1>": "0912345678"}


def test_distinct_values_get_distinct_numbers():
    res = anonymize("Bà Phạm Thu Hà và ông Đỗ Quang Huy")
    assert res.text == "Bà <PERSON_1> và ông <PERSON_2>"


def test_round_trip_restores_original():
    res = anonymize(TEXT)
    assert deanonymize(res.text, res.mapping) == normalize(TEXT)


def test_deanonymize_tolerates_llm_mangled_placeholders():
    mapping = {"<PERSON_1>": "Nguyễn Văn An"}
    llm_reply = "Đã liên hệ [PERSON_1] và < person_1 >."
    assert deanonymize(llm_reply, mapping) == "Đã liên hệ Nguyễn Văn An và Nguyễn Văn An."


def test_mapping_carries_across_messages():
    first = anonymize("khách hàng Nguyễn Văn An")
    second = anonymize("chị Lan và Nguyễn Văn An", mapping=first.mapping)
    assert second.text == "chị <PERSON_2> và <PERSON_1>"
    assert second.mapping["<PERSON_2>"] == "Lan"


def test_mask_keeps_last_four_digits_of_numbers():
    res = anonymize("STK 0011004123456 Vietcombank", operators={"BANK_ACCOUNT": "mask"})
    assert res.text == "STK *********3456 Vietcombank"


def test_redact_removes_value():
    res = anonymize("SĐT: 0912345678.", operators={"PHONE_NUMBER": "redact"})
    assert res.text == "SĐT: ."


def test_hash_is_deterministic_per_salt():
    a = anonymize("SĐT 0912345678", operators={"PHONE_NUMBER": "hash"}, salt="s1").text
    b = anonymize("gọi 0912345678", operators={"PHONE_NUMBER": "hash"}, salt="s1").text
    c = anonymize("SĐT 0912345678", operators={"PHONE_NUMBER": "hash"}, salt="s2").text
    assert a.split()[-1] == b.split()[-1] != c.split()[-1]
    assert "0912345678" not in a
