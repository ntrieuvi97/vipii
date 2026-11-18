"""Rule-based Vietnamese person-name recognizer.

No NER model: uses a surname lexicon, honorifics, context words, and exclusion
lists (places, streets named after people, common Title-Case phrases).
Plug a statistical NER in via Analyzer.add() for better recall.
"""
from __future__ import annotations

import re
from collections.abc import Iterable

from .core import Entity, _context_regex, strip_accents

SURNAMES = frozenset("""
Nguyễn Trần Lê Phạm Hoàng Huỳnh Phan Vũ Võ Đặng Bùi Đỗ Hồ Ngô Dương Lý Đào Đoàn
Đinh Lâm Lương Mai Trịnh Trương Vương Phùng Tô Tạ Cao Hà Thái Kiều Lưu Quách Châu
Từ Tăng Hứa Lục La Triệu Chu Khổng Mạc Nông Âu Diệp Hầu Khúc Lã Lại Nghiêm Phí
Thân Tiêu Tôn Ung Viên Doãn Đồng Bạch Bế Cù Cung Dư Đàm Đới Hàn Kim Lò Ninh Sầm
Tống Giáp Mạch
""".split())

HONORIFICS = frozenset("""
anh chị em ông bà cô chú bác cậu dì thím mợ bạn ngài thầy cụ mr ms mrs miss
""".split())

# Preceding words meaning "this is a place/institution named after a person".
PLACE_KEYWORDS = frozenset("""
đường phố phường quận huyện xã tỉnh thôn ấp ngõ hẻm kiệt trường cầu chợ
viện tượng lăng đền chùa tp khu bến
""".split()) | {"thành phố", "sân bay", "bệnh viện", "tượng đài"}

PLACES = frozenset(p.lower() for p in """
Hà Nội|Hà Giang|Hà Nam|Hà Tĩnh|Hà Đông|Hà Tiên|Hà Lan|Hạ Long|Hồ Chí Minh|Hồ Gươm|Hồ Tây|
Cao Bằng|Cao Lãnh|Lâm Đồng|Đồng Nai|Đồng Tháp|Đồng Hới|Đồng Xoài|Thái Nguyên|Thái Bình|
Thái Lan|Ninh Bình|Ninh Thuận|Phan Thiết|Phan Rang|Châu Đốc|Châu Âu|Châu Á|Châu Phi|
Châu Mỹ|Châu Úc|Hàn Quốc|Mai Châu|Lý Sơn|Bạch Mai|Kim Bôi|Kim Liên|Hồ Tràm|Lục Nam|
Anh Quốc|Bà Rịa|Bà Đen|Bà Chiểu|Bà Nà|Cô Tô|Ông Lãnh|Hoàng Sa|Trường Sa|Phú Quốc
""".replace("\n", "").split("|"))

# Title-Case phrases common in business documents that start with a surname.
COMMON_PHRASES = frozenset(p.lower() for p in """
Đào Tạo|Lương Thưởng|Lương Cơ|Tăng Trưởng|Tăng Cường|Từ Khóa|Từ Điển|Lý Do|Lý Thuyết|
Lý Lịch|Đồng Ý|Đồng Hồ|Đồng Nghiệp|Võ Thuật|Phí Dịch|Phí Vận|Thân Thiện|Tiêu Chuẩn|
Tiêu Chí|Tiêu Dùng|Tôn Trọng|Cung Cấp|Cung Ứng|Dư Nợ|Kim Loại|Triệu Đồng|Cao Cấp|Cao Su|
Hoàng Gia|Chu Kỳ|Thái Độ|Hứa Hẹn|Đoàn Kết|Dương Lịch|Châu Lục|Lâm Nghiệp|Lục Địa|
Vương Quốc|Phạm Vi|Lại Nói|Hà Khắc|Tô Màu|Tạ Ơn|Mai Mối|Cao Đẳng|Hồ Sơ|Mai Anh Đào|
Hoàng Hôn|Đồng Bằng|Cao Tốc|Cao Điểm|Lâm Sàng|Đào Tạo|Lý Trưởng|Đặng Thức
""".replace("\n", "").split("|"))

# "Công Tôn Nữ ...": first syllable of a compound surname that is not a surname alone.
COMPOUND_SURNAMES = frozenset({"công tôn", "tư mã", "gia cát", "thượng quan"})
# Unaccented middle names that make "Le Van Tam" / "Do Van Ha" unambiguous.
ASCII_MIDDLE = frozenset({"Van", "Thi"})

PERSON_CONTEXT = [
    "họ tên", "họ và tên", "tên", "khách hàng", "người nhận", "người gửi", "người liên hệ",
    "nhân viên", "giám đốc", "bệnh nhân", "học sinh", "sinh viên", "ký tên", "ký bởi",
    "đại diện", "người đại diện", "chủ tài khoản", "chủ tk", "ctk", "người thụ hưởng",
]

_WORD = re.compile(r"[^\W\d_]+")


SURNAMES_ASCII = frozenset(strip_accents(s) for s in SURNAMES)
# ASCII forms that collide with English words: need ALL CAPS, context or honorific.
AMBIGUOUS_ASCII = frozenset("""
To Do La Le Ha Ho Lo Mai Kim Cu Lai Tang Than Phi Ton Han Chu Thai Mac Tu Au Be Du Sam
Bach Dam Ta Lam Dong Ly
""".split())
PLACES_ASCII = frozenset(strip_accents(p) for p in PLACES)
ALL_PLACES = PLACES | PLACES_ASCII


def _is_cap(tok: str) -> bool:
    return tok[0].isupper() and (len(tok) == 1 or tok[1:].islower() or tok.isupper())


def _space_only(gap: str) -> bool:
    return gap != "" and gap.strip(" ") == ""


class PersonRecognizer:
    entity_type = "PERSON"
    name = "vn_person_rules"

    def __init__(self) -> None:
        self.context_re = _context_regex(PERSON_CONTEXT)

    def _runs(self, text: str):
        """Yield (run, preceding) for each run of space-separated capitalized tokens.

        ``preceding`` holds up to two lowercase words right before the run,
        nearest first (only words joined to the run by plain spaces).
        """
        toks = [(m.group(), m.start(), m.end()) for m in _WORD.finditer(text)]
        i = 0
        while i < len(toks):
            if not _is_cap(toks[i][0]):
                i += 1
                continue
            j = i + 1
            while j < len(toks) and _is_cap(toks[j][0]) and \
                    _space_only(text[toks[j - 1][2]:toks[j][1]]):
                j += 1
            preceding: list[str] = []
            n = i
            while n > 0 and len(preceding) < 2 and _space_only(text[toks[n - 1][2]:toks[n][1]]):
                preceding.append(toks[n - 1][0].lower())
                n -= 1
            yield toks[i:j], preceding
            i = j

    @staticmethod
    def _after_place_keyword(preceding: list[str]) -> bool:
        if preceding and preceding[0] in PLACE_KEYWORDS:
            return True
        if len(preceding) > 1:
            two = f"{preceding[1]} {preceding[0]}"
            # "thành phố X", or streets named "Bà Triệu", "Cô Giang" ("phố Bà Triệu")
            return two in PLACE_KEYWORDS or (
                preceding[0] in HONORIFICS and preceding[1] in PLACE_KEYWORDS
            )
        return False

    @staticmethod
    def _surname_kind(word: str) -> str | None:
        if word.title() in SURNAMES:
            return "vi"
        if word == strip_accents(word) and word.title() in SURNAMES_ASCII:
            return "ascii"
        return None

    @staticmethod
    def _is_place(name: str, preceding: list[str]) -> bool:
        """True if the name (or honorific + name) is, or starts with, a known place."""
        cands = {name, strip_accents(name)}
        if preceding:
            cands |= {f"{preceding[0]} {c}" for c in list(cands)}
        for c in cands:
            words = c.split(" ")
            if any(" ".join(words[:i]) in ALL_PLACES for i in range(1, len(words) + 1)):
                return True
        return False

    def find(self, text: str) -> Iterable[Entity]:
        for run, outside in self._runs(text):
            words = [t[0] for t in run]
            kinds = [self._surname_kind(w) for w in words]
            k = next((n for n, kd in enumerate(kinds) if kd), None)
            has_surname = k is not None
            if k is None:
                # "Chị Ngọc ...": a capitalised honorific opening the sentence
                k = 1 if len(words) > 1 and words[0].lower() in HONORIFICS else 0
            elif k > 0 and f"{words[k - 1]} {words[k]}".lower() in COMPOUND_SURNAMES:
                k -= 1
            # words before the name, nearest first: inside the run, then outside it
            preceding = [w.lower() for w in reversed(words[:k])] + outside
            honorific = bool(preceding) and preceding[0] in HONORIFICS
            if not has_surname and not honorific:
                continue
            if self._after_place_keyword(preceding):
                continue
            segments = self._segments(run[k:]) if has_surname else [run[k:k + 3]]
            for i, seg in enumerate(segments):
                first = i == 0
                ent = self._entity(text, seg, has_surname, honorific and first,
                                   preceding if first else [])
                if ent is not None:
                    yield ent

    def _segments(self, toks: list) -> list[list]:
        """Split "Nguyễn Văn An Trần Thị Bình" where a surname starts a 3+ word name."""
        segs, cur = [], [toks[0]]
        for i in range(1, len(toks)):
            if len(cur) >= 2 and self._surname_kind(toks[i][0]) and len(toks) - i >= 3:
                segs.append(cur)
                cur = []
            cur.append(toks[i])
        segs.append(cur)
        return segs

    def _entity(self, text: str, seg: list, has_surname: bool, honorific: bool,
                preceding: list[str]) -> Entity | None:
        n = len(seg)
        if has_surname:
            if n < 2 and not honorific:
                return None
            # Fail-closed: a name followed by Title-Case words ("Nguyễn Thị Ngọc Bảo Trâm
            # Giám Đốc") is still masked. Up to 8 words: mask the whole run (may include
            # a job title); longer runs: mask the leading 5 (the longest common names).
            if n > 8:
                seg, score = seg[:5], 0.5
            elif n >= 5:
                score = 0.5
            else:
                score = 0.6 if n >= 3 else 0.5
            words = [t[0] for t in seg]
            kind = self._surname_kind(words[0]) or (
                self._surname_kind(words[1]) if len(words) > 1 else None)
            if kind == "ascii":
                all_caps = all(w.isupper() for w in words)
                middle = len(words) >= 3 and words[1].title() in ASCII_MIDDLE
                if not middle and (
                        len(words) < 3 or (words[0].title() in AMBIGUOUS_ASCII and not all_caps)):
                    score -= 0.25
        else:
            score = 0.3

        lowered = " ".join(t[0] for t in seg).lower()
        if self._is_place(lowered, preceding) or self._is_common_phrase(lowered):
            return None
        start, end = seg[0][1], seg[-1][2]
        if honorific:
            score += 0.3
        if self.context_re is not None and \
                self.context_re.search(text[max(0, start - 30):start].lower()):
            score += 0.3
        return Entity("PERSON", start, end, text[start:end], min(score, 1.0), self.name)

    @staticmethod
    def _is_common_phrase(lowered: str) -> bool:
        words = lowered.split(" ")
        return any(" ".join(words[:i]) in COMMON_PHRASES for i in range(2, min(len(words), 3) + 1))
