"""vipii — Vietnamese PII detection & anonymization (zero dependencies, runs offline)."""
from .core import Analyzer, DenyListRecognizer, Entity, PatternRecognizer, normalize

__all__ = [
    "Analyzer",
    "AnonymizeResult",
    "DenyListRecognizer",
    "Entity",
    "PatternRecognizer",
    "analyze",
    "anonymize",
    "deanonymize",
    "normalize",
]
__version__ = "0.2.0"

_default: Analyzer | None = None


def _get_default() -> Analyzer:
    global _default
    if _default is None:
        _default = Analyzer()
    return _default


def analyze(text: str, entities=None) -> list[Entity]:
    return _get_default().analyze(text, entities)


from .anonymizer import AnonymizeResult, anonymize, deanonymize  # noqa: E402
