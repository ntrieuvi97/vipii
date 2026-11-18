"""Checksums and structural validators for Vietnamese identifiers."""
from __future__ import annotations

import re

# CCCD province codes (Thông tư 07/2016/TT-BCA). Numbers issued before the 2025
# province merger keep these codes, so the 63-province list stays authoritative.
CCCD_PROVINCE_CODES = frozenset(
    "001 002 004 006 008 010 011 012 014 015 017 019 020 022 024 025 026 027 "
    "030 031 033 034 035 036 037 038 040 042 044 045 046 048 049 051 052 054 "
    "056 058 060 062 064 066 067 068 070 072 074 075 077 079 080 082 083 084 "
    "086 087 089 091 092 093 094 095 096".split()
)

_MST_WEIGHTS = (31, 29, 23, 19, 17, 13, 7, 5, 3)


def digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def cccd_valid(value: str) -> bool:
    d = digits(value)
    return len(d) == 12 and d[:3] in CCCD_PROVINCE_CODES and d[3] in "0123"


def mst_checksum_ok(value: str) -> bool:
    d = digits(value)[:10]
    if len(d) != 10:
        return False
    check = 10 - sum(int(c) * w for c, w in zip(d[:9], _MST_WEIGHTS, strict=True)) % 11
    return check < 10 and check == int(d[9])


def luhn_ok(value: str) -> bool:
    d = digits(value)
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, c in enumerate(reversed(d)):
        n = int(c)
        if i % 2:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# Validator adapters: return None to reject, or a score delta.

def v_cccd(value: str) -> float | None:
    # 12 digits but unknown province/century code: still possible with explicit context
    # (new codes, typos) -- the -0.3 keeps it below the threshold without context.
    if len(digits(value)) != 12:
        return None
    return 0.0 if cccd_valid(value) else -0.3


def v_mst(value: str) -> float | None:
    return 0.25 if mst_checksum_ok(value) else 0.0


def v_luhn(value: str) -> float | None:
    return 0.0 if luhn_ok(value) else None


def v_phone_parens(value: str) -> float | None:
    """'(028) 3822 1234': area code in parentheses, 10-11 digits overall."""
    if value.startswith(("(0", "(2")) and len(digits(value)) not in (10, 11):
        return None
    return 0.0


def v_plate(value: str) -> float | None:
    """Plates are written with '-' or '.'; '50GB 1000' needs context to count."""
    return 0.0 if ("-" in value or "." in value) else -0.25
