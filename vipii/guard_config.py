"""Settings of ``vipii guard``: a small JSON file plus environment-variable overrides.

Defaults are the safe ones (mask everything, block prompts with PII, show the user the
masked text). The file is private (0600) and the agent cannot read or change it; see
``guard._pre``. Environment variables win over the file so CI and one-off runs can override.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = ["KEYS", "GuardConfig", "config_path", "load", "overrides", "reset", "set_value"]


@dataclass(frozen=True)
class GuardConfig:
    enabled: bool = True
    prompt: str = "block"        # block | off
    display: str = "masked"      # masked | restored (restore real values on the user's screen)
    restore_edits: bool = True   # placeholders in Edit/Write/Bash input become real values
    terms: str = ""              # "LABEL=file;LABEL=file": secret terms for custom entities


KEYS = ("enabled", "prompt", "display", "restore_edits", "terms")
_BOOLS = {"enabled", "restore_edits"}
_CHOICES = {"prompt": ("block", "off"), "display": ("masked", "restored")}
_ENV = {"enabled": "VIPII_GUARD", "prompt": "VIPII_GUARD_PROMPT", "display": "VIPII_GUARD_DISPLAY",
        "restore_edits": "VIPII_GUARD_RESTORE_EDITS", "terms": "VIPII_GUARD_TERMS"}
_TRUE, _FALSE = {"on", "true", "yes", "1"}, {"off", "false", "no", "0"}


def retry_os(fn: Callable[[], Any], attempts: int = 50) -> Any:
    """Windows reports a file that another process is replacing as PermissionError."""
    for i in range(attempts):
        try:
            return fn()
        except PermissionError:
            if i == attempts - 1:
                raise
            time.sleep(0.02)


def config_path(env: Mapping[str, str] | None = None) -> Path:
    for source in (env or {}, os.environ):
        if source.get("VIPII_GUARD_CONFIG"):
            return Path(source["VIPII_GUARD_CONFIG"])
    return Path.home() / ".vipii" / "guard-config.json"


def normalize_key(key: str) -> str:
    key = key.strip().lower().replace("-", "_")
    if key not in KEYS:
        known = ", ".join(k.replace("_", "-") for k in KEYS)
        raise ValueError(f"unknown setting {key!r} (known: {known})")
    return key


def parse_value(key: str, raw: str) -> Any:
    raw = raw.strip()
    if key in _BOOLS:
        if raw.lower() in _TRUE:
            return True
        if raw.lower() in _FALSE:
            return False
        raise ValueError(f"{key.replace('_', '-')} must be on or off, not {raw!r}")
    if key in _CHOICES:
        if raw.lower() not in _CHOICES[key]:
            raise ValueError(f"{key} must be {' or '.join(_CHOICES[key])}, not {raw!r}")
        return raw.lower()
    return raw


def _read(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(retry_os(lambda: path.read_text(encoding="utf-8")))
    except (FileNotFoundError, ValueError):
        return {}  # missing or unreadable: safe defaults, never "guard off"
    if not isinstance(data, dict):
        return {}
    clean: dict[str, Any] = {}
    for key, value in data.items():
        if key in KEYS:
            try:
                clean[key] = parse_value(key, str(value) if not isinstance(value, bool)
                                         else ("on" if value else "off"))
            except ValueError:
                pass  # an invalid value in the file falls back to the default
    return clean


def load(env: Mapping[str, str] | None = None) -> GuardConfig:
    """Effective settings: defaults, then the file, then environment variables."""
    env = os.environ if env is None else env
    values = _read(config_path(env))
    for key, name in _ENV.items():
        if env.get(name):
            try:
                values[key] = parse_value(key, env[name])
            except ValueError:
                pass
    return GuardConfig(**values)


def overrides(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Settings currently forced by an environment variable: {key: variable name}."""
    env = os.environ if env is None else env
    out = {}
    for key, name in _ENV.items():
        if env.get(name):
            try:
                parse_value(key, env[name])
                out[key] = name
            except ValueError:
                pass
    return out


def _write(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(path.parent, 0o700)
    fd, tmp = tempfile.mkstemp(prefix=".vipii-", dir=path.parent)  # mode 0600
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(dict(data), f, ensure_ascii=False, indent=2)
        retry_os(lambda: os.replace(tmp, path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def set_value(key: str, raw: str, env: Mapping[str, str] | None = None) -> Any:
    """Validate and store one setting. Raises ValueError and writes nothing when invalid."""
    key = normalize_key(key)
    value = parse_value(key, raw)
    path = config_path(env)
    data = _read(path)
    if key == "terms" and value == "":
        data.pop(key, None)
    else:
        data[key] = value
    _write(path, data)
    return value


def reset(env: Mapping[str, str] | None = None) -> None:
    try:
        config_path(env).unlink()
    except FileNotFoundError:
        pass
