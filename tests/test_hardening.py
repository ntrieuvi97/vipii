"""Hardening found during the pre-release review."""
import itertools
import random
import string

import pytest

from vipii import Analyzer, PatternRecognizer, analyze, anonymize, deanonymize, normalize


def test_empty_custom_terms_are_ignored():
    a = Analyzer(custom_terms={"PROJECT": ["", "   ", "Falcon"]})
    assert [(e.type, e.text) for e in a.analyze("dự án Falcon")] == [("PROJECT", "Falcon")]
    assert Analyzer(custom_terms={"PROJECT": [""]}).analyze("a , b") == []


def test_custom_labels_are_normalized_to_placeholder_safe_names():
    a = Analyzer(custom_terms={"project name": ["Falcon"]})
    assert [e.type for e in a.analyze("Falcon")] == ["PROJECT_NAME"]


def test_mapping_is_never_overwritten_across_calls():
    a = Analyzer(custom_terms={"project": ["Falcon", "Eagle"]})
    first = anonymize("Falcon", analyzer=a)
    second = anonymize("Eagle", analyzer=a, mapping=first.mapping)
    assert second.mapping == {"<PROJECT_1>": "Falcon", "<PROJECT_2>": "Eagle"}


def test_unparseable_entity_types_cannot_collide_with_existing_placeholders():
    r = PatternRecognizer("my-type", [(r"X\d", 0.9)])
    a = Analyzer(recognizers=[r])
    first = anonymize("X1", analyzer=a)
    second = anonymize("X2", analyzer=a, mapping=first.mapping)
    assert sorted(second.mapping.values()) == ["X1", "X2"]


# --- property / fuzz checks

PII = ["Nguyễn Văn An", "0912345678", "a.b@cty.example", "001090123456", "STK 0011004123456",
       "MST 0300588569", "30A-123.45", "chị Lan", "số 12 đường Lê Lợi, quận 1, Hà Nội"]
FILLER = ["và", "Hà Nội", "ngày 5/3", "Giá 1.200.000đ", "Công Ty", "Đào Tạo", "OK", ",", ".", "\n"]


@pytest.mark.parametrize("seed", range(300))
def test_fuzz_offsets_and_round_trip(seed):
    rng = random.Random(seed)
    parts = [rng.choice(PII + FILLER) for _ in range(rng.randint(1, 30))]
    text = " ".join(parts)
    norm = normalize(text)
    ents = analyze(text)
    for e in ents:
        assert norm[e.start:e.end] == e.text
    assert all(a.end <= b.start for a, b in itertools.pairwise(ents))
    res = anonymize(text)
    assert deanonymize(res.text, res.mapping) == norm


@pytest.mark.parametrize("seed", range(100))
def test_fuzz_random_unicode_never_crashes(seed):
    rng = random.Random(seed)
    alphabet = string.printable + "ăâđêôơưàáạảãÀÁẠẢÃĐỳýỵỷỹ0123456789/.-+@,"
    text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 400)))
    res = anonymize(text)
    assert deanonymize(res.text, res.mapping) == normalize(text) or "<" in text or "[" in text
