"""Control commands of ``vipii guard``: what ``/vipii:guard <command>`` runs.

The agent is not allowed to run these (see ``guard._pre``): only the user, from a slash
command or a terminal, can change the guard.
"""
from __future__ import annotations

import os
from collections.abc import Mapping, Sequence

from . import __version__, guard, guard_config

USAGE = """usage: vipii guard [ctl] <command>
  status                         show settings and where the hooks are installed
  enable | disable               turn the whole guard on or off (hooks stay installed)
  prompt block|off               block prompts that contain PII (default: block)
  display masked|restored        what YOU read: masked (default) or real values restored
  restore-edits on|off           placeholders in Edit/Write/Bash input become real values
  terms [LABEL=FILE;... | clear] secret terms to mask besides the built-in PII
  config [KEY [VALUE]]           show or change any setting
  reset                          back to the defaults
  install | uninstall [--project] add or remove the hooks in ~/.claude/settings.json
  purge                          delete all stored session mappings
Without a command the hook protocol is read from stdin (this is how Claude Code calls it).
"""
_ALIASES = {"restore-edits": "restore_edits", "restore_edits": "restore_edits"}
_SET = {"prompt", "display", "restore-edits", "restore_edits"}


class UsageError(ValueError):
    pass


def _onoff(value: bool) -> str:
    return "on" if value else "off"


def _show(key: str, cfg: guard_config.GuardConfig, forced: Mapping[str, str]) -> str:
    value = getattr(cfg, key)
    text = _onoff(value) if isinstance(value, bool) else (value or "(none)")
    note = f"  (set by {forced[key]})" if key in forced else ""
    return f"{key.replace('_', '-')}: {text}{note}"


def _hook_locations(env: Mapping[str, str]) -> list[str]:
    found = []
    for label, project in (("user", False), ("project", True)):
        path = guard.default_settings(project, env)
        if guard.hooks_in(path):
            found.append(f"{label}: {path}")
    return found


def status(env: Mapping[str, str]) -> str:
    cfg, forced = guard_config.load(env), guard_config.overrides(env)
    state = guard._state_dir(None, env)
    stored = len(list(state.glob("*.json"))) if state.is_dir() else 0
    where = _hook_locations(env)
    lines = [f"vipii guard {__version__}"]
    lines += [_show(k, cfg, forced) for k in guard_config.KEYS]
    lines.append(f"hooks: installed ({'; '.join(where)})" if where else "hooks: not installed")
    lines.append(f"sessions stored: {stored}")
    lines.append(f"config file: {guard_config.config_path(env)}")
    if not where:
        lines.append("run `/vipii:guard install` (or `vipii guard install`) to turn the guard on.")
    return "\n".join(lines) + "\n"


def _resync(env: Mapping[str, str]) -> list[str]:
    """Keep the registered hooks in line with the settings (the display hook is opt-in)."""
    restored = guard_config.load(env).display == "restored"
    notes = []
    for project in (False, True):
        path = guard.default_settings(project, env)
        if guard.hooks_in(path):
            result = guard.install(path, restored_display=restored)
            if result != "unchanged":
                notes.append(f"hooks updated in {path}")
    return notes


def _set(key: str, words: Sequence[str], env: Mapping[str, str]) -> str:
    if not words:
        raise UsageError(f"{key} needs a value")
    value = ";".join(words) if key.replace("-", "_") == "terms" else " ".join(words)
    stored = guard_config.set_value(key, value, env)
    shown = _onoff(stored) if isinstance(stored, bool) else (stored or "(none)")
    lines = [f"{key.replace('_', '-')} = {shown}"]
    if key.replace("-", "_") in {"display"}:
        lines += _resync(env)
    return "\n".join(lines) + "\n"


def run(words: Sequence[str], env: Mapping[str, str] | None = None,
        project: bool = False) -> tuple[int, str]:
    """Execute one control command. Returns (exit code, text for the user)."""
    env = os.environ if env is None else env
    args = [w for w in words if w != "--project"]
    project = project or "--project" in words
    if args and args[0] == "ctl":
        args = args[1:]
    cmd, rest = (args[0].lower(), args[1:]) if args else ("status", [])
    try:
        return 0, _dispatch(cmd, rest, env, project)
    except (UsageError, ValueError) as exc:
        return 2, f"vipii guard: {exc}\n\n{USAGE}"
    except OSError as exc:
        return 2, f"vipii guard: {exc}\n"


def _dispatch(cmd: str, rest: list[str], env: Mapping[str, str], project: bool) -> str:
    if cmd in {"help", "-h", "--help"}:
        return USAGE
    if cmd == "status":
        return status(env)
    if cmd in {"enable", "disable"}:
        return _set("enabled", ["on" if cmd == "enable" else "off"], env)
    if cmd in _SET:
        return _set(_ALIASES.get(cmd, cmd), rest, env)
    if cmd == "terms":
        if not rest:
            return _show("terms", guard_config.load(env), guard_config.overrides(env)) + "\n"
        if rest == ["clear"]:
            return _set_terms_clear(env)
        return _set("terms", rest, env)
    if cmd == "config":
        cfg, forced = guard_config.load(env), guard_config.overrides(env)
        if not rest:
            return "\n".join(_show(k, cfg, forced) for k in guard_config.KEYS) + "\n"
        key = guard_config.normalize_key(rest[0])
        if len(rest) == 1:
            return _show(key, cfg, forced) + "\n"
        return _set(key, rest[1:], env)
    if cmd == "reset":
        guard_config.reset(env)
        return "settings reset to the defaults\n" + "".join(n + "\n" for n in _resync(env))
    if cmd in {"install", "uninstall"}:
        path = guard.default_settings(project, env)
        restored = guard_config.load(env).display == "restored"
        result = guard.install(path, uninstall=cmd == "uninstall", restored_display=restored)
        return f"hooks {result} in {path}\n"
    if cmd == "purge":
        return f"removed {guard.purge(None, env)} stored mapping file(s)\n"
    raise UsageError(f"unknown command {cmd!r}")


def _set_terms_clear(env: Mapping[str, str]) -> str:
    guard_config.set_value("terms", "", env)
    return "terms cleared\n"
