"""Vietnamese postal-address recognizer: chains of address components.

Component kinds
  HOUSE  : [số] 12A/3 + (street keyword component | Title-Case name)
  KW     : keyword (đường, phường, quận, TP., P., Q., ...) + number and/or name
  BARE   : Title-Case name (only after the first component, e.g. ", Hà Nội")
Components are joined by commas or " - ". Lone components score low.
"""
from __future__ import annotations

import re
from collections.abc import Iterable

from .core import Entity, _context_regex
from .names import HONORIFICS


def _letters(pred) -> str:
    ranges = [(0x41, 0x5A), (0x61, 0x7A), (0xC0, 0x1B0), (0x1EA0, 0x1EF9)]
    return "".join(
        chr(c) for a, b in ranges for c in range(a, b + 1) if chr(c).isalpha() and pred(chr(c))
    )


UP = _letters(str.isupper)
LO = _letters(str.islower)

# A street/place name never swallows a Title-Case admin unit ("Lê Lợi Phường 3",
# "Lê Lợi P.14"), so those can be chained as their own components.
_NOT_ADMIN = (r"(?!(?i:phường|quận|huyện|xã|tỉnh|thành phố|thị xã|thị trấn)(?![^\W\d_]))"
              r"(?!(?:TP|Tp|KP|TX|TT|P|Q|F)(?:\.|\s*\d))")
NAMEWORD = rf"{_NOT_ADMIN}(?:[{UP}]{{2,}}(?![{LO}])|[{UP}][{LO}]*)"
NAME = rf"{NAMEWORD}(?: {NAMEWORD}){{0,4}}"
# Bounded on purpose: an unbounded "\d+(?:/\d+)*" backtracks quadratically on "1/1/1/...".
NUM = r"\d{1,6}[A-Za-z]?(?:/\d{1,6}[A-Za-z]?){0,4}"
ABBR_NUM = r"(?:P|Q|F)\d{1,2}"  # "P14 Q10" (phường 14, quận 10) written without dots

LONG_KW = [
    "tổ dân phố", "khu phố", "khu đô thị", "thị trấn", "thị xã", "thành phố", "đường", "phố",
    "ngõ", "ngách", "hẻm", "kiệt", "thôn", "xóm", "ấp", "bản", "tổ", "khu", "phường", "xã",
    "quận", "huyện", "tỉnh",
]
STREET_KW = {"đường", "phố", "ngõ", "ngách", "hẻm", "kiệt"}
ABBR_KW = ["TP", "Tp", "KP", "TX", "TT", "P", "Q"]

# Only administrative units may follow with plain spaces ("... Lê Lợi Phường 3 Quận 1");
# "bản", "khu", "tổ" are ordinary words too ("Quận 1 bản Word").
ADMIN_KW = ["thành phố", "thị xã", "thị trấn", "phường", "xã", "quận", "huyện", "tỉnh"]

_long = "|".join(re.escape(k) for k in LONG_KW)
_admin = "|".join(re.escape(k) for k in ADMIN_KW)
_abbr = "|".join(ABBR_KW)
KW = rf"(?:(?i:{_long})\s+|(?:{_abbr})(?:\.\s*|\s+))"
KW_COMP = rf"{KW}(?:{NUM}(?:\s+{NAME})?|{NAME})"
ADMIN_COMP = rf"(?:(?i:{_admin})\s+|(?:{_abbr})(?:\.\s*|\s+))(?:{NUM}(?:\s+{NAME})?|{NAME})"
HOUSE = rf"(?:(?i:số)\s+)?{NUM}\s+(?:{KW_COMP}|{NAME})"

# Never start right after '/' or a word char: "12/34" must not restart at "34".
FIRST = re.compile(rf"(?<![\w/])(?:{HOUSE}|{KW_COMP})(?!\w)")
# Next component: after a comma / " - " anything address-like (incl. a bare name such as
# ", Hà Nội"); after plain spaces only a keyword component ("... Lê Lợi P14 Q10").
NEXT = re.compile(
    rf"(?:\s*,\s*|\s+-\s+)((?:{HOUSE}|{KW_COMP}|{ABBR_NUM}|{NAME}))(?!\w)"
    rf"|\s+((?:{ADMIN_COMP}|{ABBR_NUM}))(?!\w)"
)

ADDRESS_CONTEXT = [
    "địa chỉ", "đc", "đ/c", "trú tại", "thường trú", "tạm trú", "cư trú", "nơi ở", "quê quán",
    "nguyên quán", "giao hàng đến", "giao tới", "giao đến", "address", "văn phòng", "trụ sở",
]


class AddressRecognizer:
    entity_type = "ADDRESS"
    name = "vn_address"

    def __init__(self):
        self.context_re = _context_regex(ADDRESS_CONTEXT)

    @staticmethod
    def _is_strong_single(comp: str) -> bool:
        low = comp.lower()
        return low.startswith("số ") or (any(f" {k} " in f" {low} " for k in STREET_KW) and \
            bool(re.search(r"\d", comp)))

    def find(self, text: str) -> Iterable[Entity]:
        pos = prev_end = 0
        while True:
            m = FIRST.search(text, pos)
            if not m:
                return
            start, end, comps = m.start(), m.end(), [m.group()]
            while True:
                n = NEXT.match(text, end)
                if not n:
                    break
                comp = n.group(1) or n.group(2)
                if comp.split(" ", 1)[0].lower() in HONORIFICS:
                    break  # ", Q.1 - Ông Nguyễn Văn An": a person, not an address part
                comps.append(comp)
                end = n.end()
            if len(comps) >= 2:
                score = min(0.6 + 0.1 * (len(comps) - 2), 0.85)
            else:
                score = 0.5 if self._is_strong_single(comps[0]) else 0.3
            # context must belong to this address: never look back past the previous one
            window = text[max(0, start - 30, prev_end):start]
            if self.context_re is not None and self.context_re.search(window.lower()):
                score += 0.3
            yield Entity("ADDRESS", start, end, text[start:end], min(score, 1.0), self.name)
            pos = prev_end = end
