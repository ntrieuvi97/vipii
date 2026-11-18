"""Anonymize / de-anonymize text (pseudonymization for LLM round trips)."""
from __future__ import annotations

import hashlib
import hmac
import re
import warnings
from collections.abc import Mapping
from dataclasses import dataclass, field

from .core import Analyzer, Entity, matching_view, normalize, resolve_overlaps, safe_label

OPERATORS = ("replace", "mask", "redact", "hash")
_PLACEHOLDER = re.compile(r"^<([A-Z][A-Z0-9_]*)_(\d+)>$")
# Anything deanonymize() would treat as a placeholder (ASCII only, on purpose: with
# re.IGNORECASE, Unicode lookalikes such as KELVIN SIGN would fold onto ASCII letters).
_PLACEHOLDER_LIKE = re.compile(r"[<\[]\s*([A-Za-z0-9_]+_\d+)\s*[>\]]", re.ASCII)
LITERAL = "VIPII_LITERAL"

# Long numeric identifiers: masking may keep the last 4 digits (like a bank statement).
_NUMERIC_TYPES = frozenset({"PHONE_NUMBER", "NATIONAL_ID", "TAX_CODE", "CREDIT_CARD",
                            "BANK_ACCOUNT", "SOCIAL_INSURANCE"})


@dataclass
class AnonymizeResult:
    text: str
    mapping: dict[str, str] = field(default_factory=dict)  # placeholder -> original
    entities: list[Entity] = field(default_factory=list)


def _mask(entity_type: str, value: str) -> str:
    """Hide every letter and digit; long numeric IDs keep only their last 4 digits."""
    n_digits = sum(c.isdigit() for c in value)
    keep_tail = entity_type in _NUMERIC_TYPES and n_digits >= 8
    seen, out = 0, []
    for c in value:
        if c.isdigit():
            seen += 1
            out.append(c if keep_tail and seen > n_digits - 4 else "*")
        elif c.isalnum():
            out.append("*")
        else:
            out.append(c)
    return "".join(out)


def _hash(entity_type: str, value: str, salt: str) -> str:
    """Keyed hash (HMAC-SHA256, 64 bits shown). Without a secret salt it is guessable."""
    digest = hmac.new(salt.encode(), value.encode(), hashlib.sha256).hexdigest()[:16]
    return f"<{entity_type}:{digest}>"


def _user_type(entity_type: str) -> str:
    """Placeholder-safe type; user types can never collide with the internal one."""
    t = safe_label(entity_type)
    return f"{t}_USER" if t == LITERAL else t


def _literals(text: str) -> list[Entity]:
    """Placeholder-looking text already present in the input.

    Left alone it would be "restored" by deanonymize (corrupting the text or, with a
    shared mapping, revealing another record's value). It is replaced like PII and
    restored verbatim instead.
    """
    return [Entity(LITERAL, m.start(), m.end(), text[m.start():m.end()], 2.0,
                   "placeholder_literal")
            for m in _PLACEHOLDER_LIKE.finditer(matching_view(text))]


def anonymize(
    text: str,
    analyzer: Analyzer | None = None,
    operators: Mapping[str, str] | None = None,
    default: str = "replace",
    mapping: Mapping[str, str] | None = None,
    salt: str = "",
    entities: list[str] | None = None,
) -> AnonymizeResult:
    """Detect PII and transform it.

    ``operators`` maps entity types (or the raw custom labels you used, e.g. "Dự án")
    to one of :data:`OPERATORS`. ``mapping`` from a previous call keeps placeholders
    stable across messages. The returned mapping is sensitive: store it like the
    original data, and never send it with the text.
    """
    text = normalize(text)
    if analyzer is None:
        from . import _get_default

        analyzer = _get_default()
    ops = {_user_type(k): v for k, v in (operators or {}).items()}
    for op in [*ops.values(), default]:
        if op not in OPERATORS:
            raise ValueError(f"unknown operator {op!r}; choose from {OPERATORS}")
    if not salt and "hash" in [*ops.values(), default]:
        warnings.warn("vipii: hash operator used without a secret salt; short values such "
                      "as phone numbers can be recovered by brute force", stacklevel=2)

    found = resolve_overlaps([*analyzer.analyze(text, entities), *_literals(text)])

    mapping = dict(mapping or {})
    reverse = {v: k for k, v in mapping.items()}
    counters: dict[str, int] = {}
    for ph in mapping:
        m = _PLACEHOLDER.match(ph)
        if m:
            counters[m.group(1)] = max(counters.get(m.group(1), 0), int(m.group(2)))

    pieces, last = [], 0
    for e in found:
        is_literal = e.recognizer == "placeholder_literal"
        etype = LITERAL if is_literal else _user_type(e.type)
        op = "replace" if is_literal else ops.get(etype, default)
        if op == "replace":
            existing = reverse.get(e.text)
            if existing is None:
                # never reuse a key already in the mapping (it would lose the old value)
                while True:
                    counters[etype] = counters.get(etype, 0) + 1
                    existing = f"<{etype}_{counters[etype]}>"
                    if existing not in mapping:
                        break
                mapping[existing] = e.text
                reverse[e.text] = existing
            new = existing
        elif op == "mask":
            new = _mask(etype, e.text)
        elif op == "hash":
            new = _hash(etype, e.text, salt)
        else:
            new = ""
        pieces.append(text[last:e.start])
        pieces.append(new)
        last = e.end
    pieces.append(text[last:])
    kept = [e for e in found if e.recognizer != "placeholder_literal"]
    return AnonymizeResult("".join(pieces), mapping, kept)


def deanonymize(text: str, mapping: Mapping[str, str]) -> str:
    """Put original values back. Tolerates [PERSON_1], < person_1 > etc. from LLMs.

    Single pass: restored values are never scanned again. Unknown placeholders are
    left untouched (the model invented them).
    """
    if not mapping:
        return text
    inner = {ph.strip("<>").upper(): value for ph, value in mapping.items()}

    def restore(m: re.Match) -> str:
        return inner.get(m.group(1).upper(), m.group(0))

    return _PLACEHOLDER_LIKE.sub(restore, text)
