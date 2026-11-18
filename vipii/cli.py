"""Command line: python -m vipii {analyze,anonymize,deanonymize} [FILE] ..."""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import warnings
from pathlib import Path

from . import Analyzer, anonymize, deanonymize
from .anonymizer import OPERATORS


class CliError(Exception):
    """User-facing error: printed without a traceback, exit code 2."""


def _read(path: str | None) -> str:
    try:
        if path in (None, "-"):
            return sys.stdin.read()
        return Path(path).read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise CliError(f"{path or 'stdin'}: input must be UTF-8 text") from None
    except OSError as exc:
        raise CliError(f"cannot read input: {exc}") from None


def _load_map(path: str, required: bool = False) -> dict[str, str]:
    p = Path(path)
    if not p.exists():
        if required:
            raise CliError(f"mapping file not found: {path}")
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CliError(f"cannot read mapping file {path}: {exc}") from None
    if not isinstance(data, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
        raise CliError(f"mapping file {path} must be a JSON object of strings")
    return data


def _save_map(path: str, mapping: dict) -> None:
    """Mapping holds the real values: write it owner-only (0600), atomically.

    mkstemp creates a fresh, unpredictable file with O_EXCL and mode 0600, so a
    pre-planted symlink cannot redirect the write.
    """
    directory = os.path.dirname(os.path.abspath(path))
    try:
        fd, tmp = tempfile.mkstemp(prefix=".vipii-map-", dir=directory)
    except OSError as exc:
        raise CliError(f"cannot write mapping file {path}: {exc}") from None
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(mapping, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())  # the mapping is the only key back to the data
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _terms(specs: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for spec in specs:
        label, sep, file = spec.partition("=")
        if not sep or not label or not file:
            raise CliError(f"--terms {spec!r}: expected LABEL=FILE")
        try:
            lines = Path(file).read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            raise CliError(f"--terms {spec!r}: file must be UTF-8 text") from None
        except OSError as exc:
            raise CliError(f"--terms {spec!r}: {exc}") from None
        out.setdefault(label, []).extend(
            ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")
        )
    return out


def _ops(specs: list[str]) -> dict[str, str]:
    ops = {}
    for spec in specs:
        t, _, op = spec.partition("=")
        if not t or op not in OPERATORS:
            raise CliError(f"--op {spec!r}: expected TYPE=OP with OP one of {OPERATORS}")
        ops[t] = op  # anonymize() normalizes labels ("project-x" -> PROJECT_X)
    return ops


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except CliError as exc:
        print(f"vipii: error: {exc}", file=sys.stderr)
        return 2


def _main(argv: list[str] | None) -> int:
    p = argparse.ArgumentParser(
        prog="vipii", description="Vietnamese PII detection & anonymization"
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("file", nargs="?", help="input file (default: stdin)")
        sp.add_argument("--terms", action="append", default=[], metavar="LABEL=FILE",
                        help="custom secret terms, one per line (repeatable)")
        sp.add_argument("--threshold", type=float, default=0.5)

    a = sub.add_parser("analyze", help="print detected entities as JSON")
    common(a)
    an = sub.add_parser("anonymize", help="replace PII; write mapping to --map")
    common(an)
    an.add_argument("--map", required=True, help="mapping JSON (created 0600, reused if exists)")
    an.add_argument("--op", action="append", default=[], metavar="TYPE=OP",
                    help=f"per-type operator {OPERATORS} (default replace)")
    an.add_argument("--salt", default=os.environ.get("VIPII_SALT", ""),
                    help="secret for the hash operator (prefer the VIPII_SALT env var: "
                         "command-line arguments are visible to other local users)")
    d = sub.add_parser("deanonymize", help="restore values using --map")
    d.add_argument("file", nargs="?")
    d.add_argument("--map", required=True)

    g = sub.add_parser("guard", help="Claude Code hook: reads one hook event on stdin")
    g.add_argument("--purge", action="store_true", help="delete all stored session mappings")
    g.add_argument("--install", action="store_true", help="add the guard hooks to settings.json")
    g.add_argument("--uninstall", action="store_true", help="remove the guard hooks")
    g.add_argument("--project", action="store_true",
                   help="with --install/--uninstall: use ./.claude/settings.json")
    g.add_argument("--settings", metavar="PATH",
                   help="settings file (default ~/.claude/settings.json)")

    args = p.parse_args(argv)
    if args.cmd == "guard":
        from . import guard
        if args.install or args.uninstall:
            path = Path(args.settings) if args.settings else guard.default_settings(args.project)
            try:
                status = guard.install(path, uninstall=args.uninstall)
            except ValueError as exc:
                raise CliError(str(exc)) from None
            print(f"vipii guard: hooks {status} in {path}", file=sys.stderr)
            return 0
        return guard.main(purge_state=args.purge)
    # Vietnamese text must survive non-UTF-8 locales (Windows consoles, LC_ALL=C).
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    text = _read(args.file)

    if args.cmd == "deanonymize":
        sys.stdout.write(deanonymize(text, _load_map(args.map, required=True)))
        return 0

    analyzer = Analyzer(threshold=args.threshold, custom_terms=_terms(args.terms))
    if args.cmd == "analyze":
        json.dump([e.to_dict() for e in analyzer.analyze(text)], sys.stdout,
                  ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return 0

    mapping = _load_map(args.map)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        res = anonymize(text, analyzer=analyzer, operators=_ops(args.op),
                        mapping=mapping, salt=args.salt)
    for w in caught:
        print(f"warning: {w.message}", file=sys.stderr)
    _save_map(args.map, res.mapping)
    sys.stdout.write(res.text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
