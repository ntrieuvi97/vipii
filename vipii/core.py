"""Core types: Entity, PatternRecognizer, Analyzer (overlap resolution, NFC)."""
from __future__ import annotations

import bisect
import hashlib
import re
import unicodedata
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Protocol


@dataclass(frozen=True)
class Entity:
    type: str
    start: int
    end: int
    text: str
    score: float
    recognizer: str = ""

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "start": self.start,
            "end": self.end,
            "text": self.text,
            "score": round(self.score, 3),
            "recognizer": self.recognizer,
        }


class Recognizer(Protocol):
    name: str
    entity_type: str

    def find(self, text: str) -> Iterable[Entity]: ...


def normalize(text: str) -> str:
    """Vietnamese text often arrives in NFD (decomposed) form. Work in NFC."""
    return unicodedata.normalize("NFC", text)


def strip_accents(s: str) -> str:
    """'Nguyễn Đức' -> 'Nguyen Duc' (also maps đ/Đ, which NFD does not decompose)."""
    s = unicodedata.normalize("NFD", s.replace("đ", "d").replace("Đ", "D"))
    return "".join(c for c in s if not unicodedata.combining(c))


def _invisible_table() -> dict[int, str]:
    """Characters matched as ' ' so they cannot hide or split a value.

    * Unicode spaces (NBSP from Word/web, thin spaces...)
    * every format character (category Cf: zero-width space/joiners, soft hyphen, BOM,
      LRM/RLM and other bidi controls, invisible operators, tag characters...)
    * invisible fillers that are not Cf (combining grapheme joiner, Hangul fillers,
      Khmer inherent vowels).
    The swap is one character for one character, so offsets are shared with the
    original text; recognizers accept short runs of separators.
    """
    table = {ord(c): " " for c in "\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005"
             "\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000"
             "\u034f\u115f\u1160\u3164\uffa0\u17b4\u17b5"}
    for cp in [*range(0x10000), *range(0xE0000, 0xE0080)]:
        if unicodedata.category(chr(cp)) == "Cf":
            table[cp] = " "
    return table


_SPACES = _invisible_table()


def matching_view(text: str) -> str:
    return text.translate(_SPACES)


def _context_regex(words: Sequence[str]) -> re.Pattern | None:
    """Whole-word match of any word, with or without diacritics ('tài khoản'/'tai khoan').

    A keyword may be glued to an index digit ('STK1:'), but not to another letter.
    """
    variants = {v for w in words for v in (w.lower(), strip_accents(w.lower()))}
    if not variants:
        return None
    alts = "|".join(re.escape(w) for w in sorted(variants, key=len, reverse=True))
    return re.compile(rf"(?<!\w)(?:{alts})(?![^\W\d_])")


# A validator gets the matched text and returns None (reject) or a score delta.
Validator = Callable[[str], float | None]

# A run of 3+ digits is "another value"; 1-2 digits are part of a label ("STK1", "số 2").
_LAST_NUMBER = re.compile(r"\d{3,}(?!.*\d{3})", re.S)
_FIRST_NUMBER = re.compile(r"\d{3,}")


class PatternRecognizer:
    """Regex patterns + optional validator + context-word boost.

    Patterns may define a named group ``v``; if present only that group is
    reported as the entity span (lets a pattern require surrounding keywords).
    """

    def __init__(
        self,
        entity_type: str,
        patterns: Sequence[tuple[str, float]],
        context: Sequence[str] = (),
        context_boost: float = 0.35,
        validator: Validator | None = None,
        name: str | None = None,
        flags: int = 0,
        window_before: int = 40,
        window_after: int = 20,
        anti_context: Sequence[str] = (),
        anti_penalty: float = 0.3,
        anti_floor: float = 0.5,
    ):
        self.entity_type = entity_type
        self.name = name or f"{entity_type.lower()}_pattern"
        self.patterns = [(re.compile(p, flags), s) for p, s in patterns]
        self.context_re = _context_regex(context)
        self.context_boost = context_boost
        self.validator = validator
        self.window_before = window_before
        self.window_after = window_after
        # words that say "this is something else" (e.g. "MST" next to a phone-shaped number)
        self.anti_re = _context_regex(anti_context)
        self.anti_penalty = anti_penalty
        self.anti_floor = anti_floor

    def _windows(self, text: str, start: int, end: int) -> tuple[str, str]:
        before = text[max(0, start - self.window_before):start]
        after = text[end:end + self.window_after]
        # A keyword sitting before another number belongs to that number:
        # cut each window at the nearest other value ("đt 0283..., MST 0300...").
        last = _LAST_NUMBER.search(before)
        if last:
            before = before[last.end():]
        first = _FIRST_NUMBER.search(after)
        if first:
            after = after[:first.start()]
        return before.lower(), after.lower()

    @staticmethod
    def _hit(regex: re.Pattern | None, windows: Sequence[str]) -> bool:
        return regex is not None and any(regex.search(w) for w in windows)

    def has_context(self, text: str, start: int, end: int) -> bool:
        return self._hit(self.context_re, self._windows(text, start, end))

    def score_context(self, text: str, start: int, end: int, score: float) -> float:
        windows = self._windows(text, start, end)
        if self._hit(self.context_re, windows):
            score += self.context_boost
        # Anti-context only looks back: a label *after* a value usually introduces the
        # next value ("0912345678, MST 0300588569"). It is a tie-breaker, never a reason
        # to drop a value: the penalty cannot push a score below ``anti_floor`` (the
        # default threshold), so "ảnh CCCD ... 0987654321" stays masked (fail-closed).
        if self._hit(self.anti_re, (windows[0],)):
            score = max(score - self.anti_penalty, min(score, self.anti_floor))
        return score

    def find(self, text: str) -> Iterable[Entity]:
        for regex, base in self.patterns:
            for m in regex.finditer(text):
                if "v" in regex.groupindex:
                    start, end = m.span("v")
                else:
                    start, end = m.span()
                value = text[start:end]
                score = base
                if self.validator is not None:
                    delta = self.validator(value)
                    if delta is None:
                        continue
                    score += delta
                score = self.score_context(text, start, end, score)
                yield Entity(self.entity_type, start, end, value, min(score, 1.0), self.name)


def resolve_overlaps(entities: Iterable[Entity]) -> list[Entity]:
    """Greedy: highest score first, then longest span; drop anything overlapping.

    Chosen spans never overlap, so only the chosen span with the greatest start
    below ``e.end`` can collide with ``e``: O(n log n) via bisect.
    """
    starts: list[int] = []
    chosen: list[Entity] = []
    for e in sorted(entities, key=lambda e: (-e.score, -(e.end - e.start), e.start)):
        i = bisect.bisect_left(starts, e.end)
        if i > 0 and chosen[i - 1].end > e.start:
            continue
        starts.insert(i, e.start)
        chosen.insert(i, e)
    return chosen


def safe_label(label: str) -> str:
    """Entity types end up inside placeholders like <DU_AN_1>: keep them [A-Z0-9_].

    Vietnamese labels are transliterated first ('Dự án' -> 'DU_AN').
    """
    ascii_label = strip_accents(normalize(label)).upper()
    safe = re.sub(r"[^A-Z0-9]+", "_", ascii_label).strip("_")
    if not safe:  # non-Latin label ('日本'): keep distinct labels distinct
        safe = "CUSTOM_" + hashlib.sha256(normalize(label).encode()).hexdigest()[:6].upper()
    return safe


class DenyListRecognizer:
    """Organisation-specific secrets: project names, codenames, client names..."""

    def __init__(self, entity_type: str, terms: Sequence[str]):
        self.entity_type = safe_label(entity_type)
        self.name = f"deny_list_{self.entity_type.lower()}"
        cleaned = sorted({normalize(t).strip() for t in terms} - {""}, key=len, reverse=True)
        self.regex = (
            re.compile(rf"(?<!\w)(?:{'|'.join(map(re.escape, cleaned))})(?!\w)", re.IGNORECASE)
            if cleaned else None
        )

    def find(self, text: str) -> Iterable[Entity]:
        if self.regex is None:
            return
        for m in self.regex.finditer(text):
            yield Entity(self.entity_type, m.start(), m.end(), m.group(), 1.0, self.name)


class Analyzer:
    def __init__(
        self,
        recognizers: Sequence[Recognizer] | None = None,
        threshold: float = 0.5,
        custom_terms: Mapping[str, Sequence[str]] | None = None,
    ):
        if recognizers is None:
            from .recognizers import default_recognizers

            recognizers = default_recognizers()
        self.recognizers = list(recognizers)
        self.threshold = threshold
        for label, terms in (custom_terms or {}).items():
            if terms:
                self.recognizers.append(DenyListRecognizer(label, terms))

    def add(self, recognizer: Recognizer) -> Analyzer:
        self.recognizers.append(recognizer)
        return self

    def analyze(self, text: str, entities: Sequence[str] | None = None) -> list[Entity]:
        """Return entities found in ``normalize(text)`` (offsets refer to the NFC text).

        Recognizers see a view where Unicode spaces are plain spaces; reported
        ``Entity.text`` is always the original NFC slice.
        """
        text = normalize(text)
        view = matching_view(text)
        found: list[Entity] = []
        for r in self.recognizers:
            if entities is not None and r.entity_type not in entities:
                continue
            found.extend(e for e in r.find(view) if e.score >= self.threshold)
        chosen = resolve_overlaps(found)
        if view == text:
            return chosen
        return [replace(e, text=text[e.start:e.end]) for e in chosen]
