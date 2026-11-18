"""Built-in recognizers for Vietnamese PII."""
from __future__ import annotations

import re
from collections.abc import Iterable

from .address import AddressRecognizer
from .core import Entity, PatternRecognizer
from .names import PersonRecognizer
from .validators import v_cccd, v_mst, v_phone_parens, v_plate

SEP = r"[ .\-]{0,3}"  # short runs: "0987  654321", invisible chars become spaces

# Labels of other numeric identifiers: a phone-shaped number next to them is not a phone.
NOT_A_PHONE = ["mst", "mã số thuế", "msdn", "mã số doanh nghiệp", "stk", "số tk",
               "số tài khoản", "cccd", "cmnd", "căn cước", "bhxh", "mã số bhxh", "bhyt"]


def phone_recognizer() -> PatternRecognizer:
    mobile = rf"(?<![\w+])(?:\+84|0084|0){SEP}[35789](?:{SEP}\d){{8}}(?!\w)"
    landline = rf"(?<![\w+])(?:\+84|0){SEP}2(?:{SEP}\d){{9}}(?!\w)"
    paren_cc = rf"(?<!\w)\(\+?84\)\s?(?:[35789](?:{SEP}\d){{8}}|2(?:{SEP}\d){{9}})(?!\w)"
    paren_area = rf"(?<!\w)\(0?2\d{{1,2}}\)\s?\d(?:{SEP}\d){{6,7}}(?!\w)"
    bare_cc = r"(?<![\w+])84[35789]\d{8}(?!\w)"
    return PatternRecognizer(
        "PHONE_NUMBER",
        [(mobile, 0.6), (landline, 0.5), (paren_cc, 0.6), (paren_area, 0.5), (bare_cc, 0.45)],
        context=["sđt", "số điện thoại", "điện thoại", "đt", "di động", "hotline",
                 "liên hệ", "gọi", "zalo", "phone", "tel", "fax", "mobile"],
        anti_context=NOT_A_PHONE,
        validator=v_phone_parens,
        name="vn_phone",
    )


ID_CONTEXT = ["cccd", "căn cước", "căn cước công dân", "cmnd", "chứng minh nhân dân",
              "chứng minh thư", "số định danh", "định danh cá nhân", "id card", "national id"]


def cccd_recognizer() -> PatternRecognizer:
    # Unknown province code: only with explicit context (validator gives -0.3).
    return PatternRecognizer(
        "NATIONAL_ID",
        [(r"(?<!\w)\d{12}(?!\w)", 0.55),
         (r"(?<![\w.])\d{3}([ .])\d{3}\1\d{3}\1\d{3}(?!\w|\.\d)", 0.55)],
        context=ID_CONTEXT,
        validator=v_cccd,
        name="vn_cccd",
    )


def cmnd_recognizer() -> PatternRecognizer:
    # 9-digit legacy ID: far too generic to report without context.
    return PatternRecognizer(
        "NATIONAL_ID",
        [(r"(?<!\w)\d{9}(?!\w)", 0.2),
         (r"(?<![\w.])\d{3}([ .])\d{3}\1\d{3}(?![\w.]|[ .]\d)", 0.2)],
        context=ID_CONTEXT,
        context_boost=0.4,
        name="vn_cmnd",
    )


def tax_code_recognizer() -> PatternRecognizer:
    # base 0.2, +0.25 if checksum valid, +0.35 with context: context is always required
    # (valid checksum alone = 0.45), and context alone (0.55) beats a phone-shaped number
    # whose anti-context ("mã số thuế") floors it at 0.5.
    return PatternRecognizer(
        "TAX_CODE",
        [(r"(?<!\w)\d{10}(?:-\d{3})?(?![\w-])", 0.2)],
        context=["mst", "mã số thuế", "mã số doanh nghiệp", "msdn", "mã số dn",
                 "tax code", "tax id", "mã thuế"],
        validator=v_mst,
        name="vn_tax_code",
    )


BANKS = ["vietcombank", "vcb", "vietinbank", "bidv", "agribank", "techcombank", "tcb",
         "mbbank", "mb bank", "mb", "acb", "vpbank", "tpbank", "sacombank", "shb", "hdbank",
         "vib", "ocb", "msb", "seabank", "eximbank", "scb", "lpbank", "bac a bank",
         "nam a bank", "pvcombank", "abbank", "kienlongbank", "vietabank", "baovietbank"]

CARD_IIN = ("9704", "4", "51", "52", "53", "54", "55", "22", "23", "24", "25", "26", "27",
            "34", "37", "35", "62")


class CardRecognizer(PatternRecognizer):
    """Card numbers: 13-19 digits, known IIN, Luhn.

    Candidates come from maximal runs of digit groups ("22 02 2026 4111 1111 1111
    1111"). Every start/end on a group boundary is tried and overlapping valid
    candidates are merged, so a card is masked whole even when other numbers are
    glued to it (fail-closed: the neighbouring digits may be masked too).
    Luhn uses parity prefix sums: O(1) per candidate, linear overall.
    """

    _RUN = re.compile(r"(?<!\w)\d(?:[ .\-]{0,3}\d)*")
    _DOUBLED = (0, 2, 4, 6, 8, 1, 3, 5, 7, 9)

    def __init__(self) -> None:
        super().__init__(
            "CREDIT_CARD", [],
            context=["thẻ", "card", "visa", "mastercard", "napas", "atm", "số thẻ", "jcb"],
            context_boost=0.3,
            name="card_luhn",
        )

    def _candidates(self, text: str, run: re.Match) -> list[tuple[int, int]]:
        pos = [run.start() + i for i, c in enumerate(run.group()) if c.isdigit()]
        d = [int(text[p]) for p in pos]
        n = len(d)
        if n < 13:
            return []
        glued = run.end() < len(text) and text[run.end()].isalnum()  # "... 1111 15h"
        is_start = [i == 0 or pos[i - 1] != pos[i] - 1 for i in range(n)]
        is_end = [(i == n - 1 and not glued) or (i < n - 1 and pos[i + 1] != pos[i] + 1)
                  for i in range(n)]
        # plain[p][i] / dbl[p][i]: sum of digits (or doubled digits) at indices < i with
        # index parity p. In a candidate ending at e, digits with the parity of e are
        # plain and the others doubled.
        plain = [[0] * (n + 1), [0] * (n + 1)]
        dbl = [[0] * (n + 1), [0] * (n + 1)]
        for i, v in enumerate(d):
            for p in (0, 1):
                hit = (i & 1) == p
                plain[p][i + 1] = plain[p][i] + (v if hit else 0)
                dbl[p][i + 1] = dbl[p][i] + (self._DOUBLED[v] if hit else 0)
        digits_str = "".join(map(str, d))
        found = []
        for s in range(n - 12):
            if not is_start[s] or not digits_str.startswith(CARD_IIN, s):
                continue
            for e in range(min(s + 18, n - 1), s + 11, -1):
                if not is_end[e]:
                    continue
                pe = e & 1
                total = (plain[pe][e + 1] - plain[pe][s]) + (dbl[1 - pe][e + 1] - dbl[1 - pe][s])
                if total % 10 == 0:
                    found.append((pos[s], pos[e] + 1))
                    break
        return found

    def find(self, text: str) -> Iterable[Entity]:
        for run in self._RUN.finditer(text):
            spans = sorted(self._candidates(text, run))
            merged: list[list[int]] = []
            for start, end in spans:
                if merged and start < merged[-1][1]:
                    merged[-1][1] = max(merged[-1][1], end)
                else:
                    merged.append([start, end])
            for start, end in merged:
                score = self.score_context(text, start, end, 0.6)
                yield Entity("CREDIT_CARD", start, end, text[start:end], min(score, 1.0),
                             self.name)


def bank_account_recognizer() -> PatternRecognizer:
    return PatternRecognizer(
        "BANK_ACCOUNT",
        [(r"(?<![\w-])\d{6,19}(?![\w-])", 0.1)],
        context=["stk", "số tk", "tk", "số tài khoản", "tài khoản", "account", "acc no",
                 "chuyển khoản", "ck", "ngân hàng", "bank", *BANKS],
        context_boost=0.5,
        name="vn_bank_account",
    )


def email_recognizer() -> PatternRecognizer:
    return PatternRecognizer(
        "EMAIL",
        [(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+(?<!\.)", 0.9)],
        name="email",
    )


def license_plate_recognizer() -> PatternRecognizer:
    # Without a '-' or '.' ("50GB 1000", "30A 1234") a plate needs context (validator).
    prov = r"(?:1[1-9]|[2-9]\d)"
    serial = r"(?:\d{3}\.\d{2}|\d{4,5})"
    car = rf"(?<![\w-]){prov}[A-Z]{{1,2}}[ -]?{serial}(?!\w|\.\d)"
    moto = rf"(?<![\w-]){prov}-?[A-Z][A-Z0-9][ -]?{serial}(?!\w|\.\d)"
    return PatternRecognizer(
        "LICENSE_PLATE",
        [(car, 0.55), (moto, 0.55)],
        context=["biển số", "biển kiểm soát", "bks", "bsx", "xe", "ô tô", "xe máy", "plate"],
        context_boost=0.3,
        validator=v_plate,
        name="vn_license_plate",
    )


def passport_recognizer() -> PatternRecognizer:
    return PatternRecognizer(
        "PASSPORT",
        [(r"(?<!\w)[A-Z]\d{7}(?!\w)", 0.25)],
        context=["hộ chiếu", "passport", "số hc", "hc số"],
        context_boost=0.4,
        name="vn_passport",
    )


def date_of_birth_recognizer() -> PatternRecognizer:
    day = r"(?:0?[1-9]|[12]\d|3[01])"
    month = r"(?:0?[1-9]|1[0-2])"
    year = r"(?:19|20)\d{2}"
    numeric = rf"(?<![\d/.-]){day}[/.-]{month}[/.-]{year}(?![\d/.-])"
    words = rf"(?<!\d){day}\s+tháng\s+{month}\s+năm\s+{year}(?!\d)"
    iso = r"(?<![\d/.-])(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])(?![\d/.-])"
    return PatternRecognizer(
        "DATE_OF_BIRTH",
        [(numeric, 0.15), (words, 0.15), (iso, 0.15)],
        context=["sinh ngày", "ngày sinh", "sinh năm", "năm sinh", "ns", "sn", "dob",
                 "date of birth", "ngày tháng năm sinh"],
        context_boost=0.4,
        window_before=25,
        window_after=0,
        flags=re.IGNORECASE,
        name="vn_dob",
    )


def social_insurance_recognizer() -> PatternRecognizer:
    return PatternRecognizer(
        "SOCIAL_INSURANCE",
        [(r"(?<!\w)\d{10}(?!\w)", 0.15)],
        context=["bhxh", "bảo hiểm xã hội", "sổ bhxh", "bhyt", "bảo hiểm y tế", "thẻ bhyt"],
        context_boost=0.45,
        name="vn_social_insurance",
    )


def default_recognizers() -> list:
    # Order matters only for exact score ties (earlier wins).
    return [
        email_recognizer(),
        phone_recognizer(),
        CardRecognizer(),
        cccd_recognizer(),
        cmnd_recognizer(),
        tax_code_recognizer(),
        social_insurance_recognizer(),
        bank_account_recognizer(),
        license_plate_recognizer(),
        passport_recognizer(),
        date_of_birth_recognizer(),
        PersonRecognizer(),
        AddressRecognizer(),
    ]
