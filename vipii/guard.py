"""vipii guard: Claude Code hooks that keep raw PII away from the model.

A skill only *asks* the agent to mask data. These hooks *enforce* it at the tool layer:

* ``PostToolUse``      masks every string in a tool result before the model sees it
  (``updatedToolOutput``): file reads, shell output, web fetches, MCP tools.
* ``PreToolUse``       turns placeholders in Edit/Write/Bash input back into real values
  so the agent can edit a masked file; denies reading the mapping files and image/PDF
  files that cannot be masked.
* ``UserPromptSubmit`` blocks a prompt that contains PII and shows a masked copy.
* ``MessageDisplay``   restores real values in what *you* read; the model keeps placeholders.

Hooks are separate processes, so the placeholder mapping is a private per-session file.
Every failure path ends in "withheld" or "blocked", never in "original shown".
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .anonymizer import anonymize, deanonymize
from .core import Analyzer

__all__ = ["deanonymize", "handle", "install", "main", "purge", "run"]

LOCK_TIMEOUT = 5.0
LOCK_STALE = 30.0
PRUNE_AFTER = 7 * 24 * 3600
WITHHELD = "[vipii guard: output withheld, it could not be masked safely]"
ALLOW_MARKER = "#allow-pii"
BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".heic",
                   ".pdf", ".mp3", ".wav", ".mp4", ".mov"}
BINARY_TYPES = {"image", "pdf", "audio", "video", "document"}
RESTORE_TOOLS = {"Edit", "MultiEdit", "Write", "Bash", "NotebookEdit"}
KEEP_WHEN_WITHHOLDING = {"type", "mode", "media_type"}  # keep the output schema valid


# ----------------------------------------------------------------------------- state

def _state_dir(explicit: str | Path | None, env: Mapping[str, str]) -> Path:
    if explicit is not None:
        return Path(explicit)
    return Path(env.get("VIPII_GUARD_DIR") or Path.home() / ".vipii" / "guard")


def _session_file(state: Path, event: Mapping[str, Any]) -> Path:
    sid = re.sub(r"[^A-Za-z0-9_-]", "_", str(event.get("session_id") or "default"))[:80]
    return state / f"{sid}.json"


def _ensure_dir(state: Path) -> None:
    state.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(state, 0o700)


def _prune(state: Path, keep: Path) -> None:
    cutoff = time.time() - PRUNE_AFTER
    for p in state.glob("*.json"):
        try:
            if p != keep and p.stat().st_mtime < cutoff:
                p.unlink()
        except OSError:
            pass


class _Lock:
    """Cross-process, cross-thread lock: exclusive creation of ``<file>.lock``."""

    def __init__(self, path: Path):
        self.path = Path(f"{path}.lock")

    def __enter__(self) -> _Lock:
        deadline = time.monotonic() + LOCK_TIMEOUT
        while True:
            try:
                os.close(os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
                return self
            except (FileExistsError, PermissionError):  # Windows: delete pending = busy
                try:
                    if time.time() - self.path.stat().st_mtime > LOCK_STALE:
                        self.path.unlink()  # a crashed hook left it behind
                        continue
                except OSError:
                    continue
                if time.monotonic() > deadline:
                    raise TimeoutError("mapping file is locked") from None
                time.sleep(0.01)

    def __exit__(self, *exc: object) -> None:
        try:
            self.path.unlink()
        except OSError:
            pass


def _retry_os(fn: Callable[[], Any], attempts: int = 50) -> Any:
    """Windows reports a file that another process is replacing as PermissionError."""
    for i in range(attempts):
        try:
            return fn()
        except PermissionError:
            if i == attempts - 1:
                raise
            time.sleep(0.02)


def _load(path: Path) -> dict[str, str]:
    try:
        text = _retry_os(lambda: path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}  # any other OSError propagates: never mistake "busy" for "corrupt"
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except ValueError:
        pass
    try:  # not valid JSON: keep the evidence aside and start a fresh mapping
        path.replace(path.with_suffix(f".corrupt-{int(time.time())}"))
    except OSError:
        pass
    return {}


def _save(path: Path, mapping: Mapping[str, str]) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".vipii-", dir=path.parent)  # mode 0600
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(mapping, f, ensure_ascii=False)
        _retry_os(lambda: os.replace(tmp, path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ----------------------------------------------------------------------------- masking

def _analyzer(env: Mapping[str, str]) -> Analyzer:
    spec = env.get("VIPII_GUARD_TERMS", "")
    if not spec:
        from . import _get_default
        return _get_default()
    from .cli import _terms
    return Analyzer(custom_terms=_terms([s for s in spec.split(";") if s]))


def _walk(obj: Any, fn: Callable[[str], str], key: str | None = None) -> Any:
    if isinstance(obj, str):
        return fn(obj) if obj.strip() else obj
    if isinstance(obj, list):
        return [_walk(x, fn) for x in obj]
    if isinstance(obj, dict):
        return {k: _walk(v, fn, k) for k, v in obj.items()}
    return obj


def _mask_text(text: str, mapping: dict[str, str], analyzer: Analyzer) -> str:
    res = anonymize(text, analyzer=analyzer, mapping=mapping)
    mapping.update(res.mapping)
    return res.text


def _is_binary(obj: Any) -> bool:
    if isinstance(obj, list):
        return any(_is_binary(x) for x in obj)
    if not isinstance(obj, dict):
        return False
    kind = str(obj.get("type", "")).lower()
    media = str(obj.get("media_type", "")).lower()
    if (kind in BINARY_TYPES or obj.get("isImage") is True or "base64" in obj
            or (kind == "base64" and "data" in obj)
            or media.startswith(("image/", "audio/", "video/", "application/pdf"))):
        return True
    return any(_is_binary(v) for v in obj.values())


def _withhold(obj: Any) -> Any:
    if isinstance(obj, str):
        return WITHHELD
    if isinstance(obj, list):
        return [_withhold(x) for x in obj]
    if isinstance(obj, dict):
        return {k: (v if k in KEEP_WHEN_WITHHOLDING and isinstance(v, str) else _withhold(v))
                for k, v in obj.items()}
    return obj


# ----------------------------------------------------------------------------- events

def _hook(kind: str, **fields: Any) -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": kind, **fields}}


def _post(event: dict, state: Path, env: Mapping[str, str]) -> dict | None:
    resp = event.get("tool_response")
    if resp is None:
        return None
    if _is_binary(resp):
        new = _withhold(resp)
    else:
        analyzer = _analyzer(env)
        _ensure_dir(state)
        path = _session_file(state, event)
        with _Lock(path):
            mapping = _load(path)
            before = dict(mapping)
            new = _walk(resp, lambda s: _mask_text(s, mapping, analyzer))
            if mapping != before:
                _save(path, mapping)
        _prune(state, keep=path)
    return None if new == resp else _hook("PostToolUse", updatedToolOutput=new)


def _touches_state(tool_input: Any, state: Path) -> bool:
    flat = json.dumps(tool_input, ensure_ascii=False).replace("\\\\", "/").lower()
    return str(state).replace("\\", "/").lower() in flat or ".vipii/guard" in flat


def _deny(reason: str) -> dict:
    return _hook("PreToolUse", permissionDecision="deny", permissionDecisionReason=reason)


def _pre(event: dict, state: Path, env: Mapping[str, str]) -> dict | None:
    tool = str(event.get("tool_name", ""))
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    if _touches_state(tool_input, state):
        return _deny("vipii guard: the session mapping files hold the real values and are "
                     "not available to the agent.")
    suffix = Path(str(tool_input.get("file_path", ""))).suffix.lower()
    if tool == "Read" and suffix in BINARY_SUFFIXES:
        return _deny("vipii guard: images, PDFs and media cannot be masked. Convert them to "
                     "text, mask the text with `vipii anonymize`, and read that copy.")
    if tool not in RESTORE_TOOLS:
        return None
    mapping = _load(_session_file(state, event))
    if not mapping:
        return None
    new = _walk(tool_input, lambda s: deanonymize(s, mapping))
    return None if new == tool_input else _hook("PreToolUse", updatedInput=new)


def _prompt(event: dict, state: Path, env: Mapping[str, str]) -> dict | None:
    if env.get("VIPII_GUARD_PROMPT", "block").lower() == "off":
        return None
    text = str(event.get("prompt", ""))
    if ALLOW_MARKER in text:
        return None
    analyzer = _analyzer(env)
    found = analyzer.analyze(text)
    if not found:
        return None
    _ensure_dir(state)
    path = _session_file(state, event)
    with _Lock(path):
        mapping = _load(path)
        masked = _mask_text(text, mapping, analyzer)
        _save(path, mapping)
    kinds = ", ".join(f"{t}×{n}" for t, n in sorted(Counter(e.type for e in found).items()))
    reason = (f"vipii guard chặn prompt này vì có dữ liệu cá nhân ({kinds}). "
              f"Bản đã che, hãy copy và gửi lại:\n\n{masked}\n\n"
              f"(Cố ý gửi nguyên văn: thêm {ALLOW_MARKER} vào prompt. "
              f"vipii guard blocked this prompt: masked copy above.)")
    return {"decision": "block", "reason": reason,
            **_hook("UserPromptSubmit", suppressOriginalPrompt=True)}


def _display(event: dict, state: Path, env: Mapping[str, str]) -> dict | None:
    delta = event.get("delta")
    if not isinstance(delta, str) or not delta:
        return None
    mapping = _load(_session_file(state, event))
    if not mapping:
        return None
    shown = deanonymize(delta, mapping)
    return None if shown == delta else _hook("MessageDisplay", displayContent=shown)


def _failsafe(event: dict, kind: str) -> dict | None:
    """The guard itself broke: refuse, never pass the original through."""
    if kind == "PostToolUse":
        try:
            return _hook("PostToolUse", updatedToolOutput=_withhold(event.get("tool_response")))
        except Exception:
            return _hook("PostToolUse", updatedToolOutput=WITHHELD)
    if kind == "UserPromptSubmit":
        return {"decision": "block", "reason": "vipii guard failed and blocked this prompt "
                "(fail-closed). Set VIPII_GUARD=off to disable the guard.",
                **_hook("UserPromptSubmit", suppressOriginalPrompt=True)}
    if kind == "PreToolUse":
        return _deny("vipii guard failed (fail-closed). Set VIPII_GUARD=off to disable it.")
    return None  # MessageDisplay and others: the original text only holds placeholders


_HANDLERS = {"PostToolUse": _post, "PreToolUse": _pre, "UserPromptSubmit": _prompt,
             "MessageDisplay": _display}


def handle(event: dict, state_dir: str | Path | None = None,
           env: Mapping[str, str] | None = None) -> dict | None:
    """Map one hook event to the JSON the hook must print (None = print nothing)."""
    env = os.environ if env is None else env
    if env.get("VIPII_GUARD", "").lower() in {"off", "0", "false"}:
        return None
    kind = str(event.get("hook_event_name", ""))
    fn = _HANDLERS.get(kind)
    if fn is None:
        return None
    try:
        return fn(event, _state_dir(state_dir, env), env)
    except Exception:
        return _failsafe(event, kind)


def run(stdin_text: str, state_dir: str | Path | None = None,
        env: Mapping[str, str] | None = None) -> tuple[int, str, str]:
    """Hook protocol: (exit code, stdout, stderr). Unreadable input is an error."""
    try:
        event = json.loads(stdin_text)
        if not isinstance(event, dict):
            raise ValueError("hook input must be a JSON object")
    except ValueError as exc:
        return 2, "", f"vipii guard: invalid hook input: {exc}\n"
    out = handle(event, state_dir, env)
    return 0, (json.dumps(out, ensure_ascii=True) if out else ""), ""


def purge(state_dir: str | Path | None = None, env: Mapping[str, str] | None = None) -> int:
    """Delete every stored mapping. Returns the number of files removed."""
    state = _state_dir(state_dir, os.environ if env is None else env)
    count = 0
    for pattern in ("*.json", "*.lock", "*.corrupt-*"):
        for p in state.glob(pattern):
            try:
                p.unlink()
                count += 1
            except OSError:
                pass
    return count


_FAIL_CLOSED = {"PostToolUse", "PreToolUse", "UserPromptSubmit"}
_EVENTS = [("PreToolUse", "*"), ("PostToolUse", "*"), ("UserPromptSubmit", None),
           ("MessageDisplay", None)]


def _is_ours(handler: Mapping[str, Any]) -> bool:
    return handler.get("args") == ["-m", "vipii", "guard"]


def install(settings: Path, python: str | None = None, uninstall: bool = False) -> str:
    """Add (or remove) the guard hooks in a Claude Code ``settings.json``.

    Other settings and hooks are kept, the file is replaced atomically, the previous
    version is saved as ``settings.json.vipii-bak``, and running it twice changes nothing.
    The interpreter is stored as an absolute path, so hooks do not depend on ``PATH``.
    """
    python = python or sys.executable
    try:
        raw = settings.read_text(encoding="utf-8")
        data = json.loads(raw) if raw.strip() else {}
        if not isinstance(data, dict):
            raise ValueError("top level is not an object")
    except FileNotFoundError:
        raw, data = "", {}
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read {settings}: {exc} (nothing was changed)") from None

    hooks = data.setdefault("hooks", {})
    for event, groups in list(hooks.items()):  # drop previous guard entries everywhere
        kept = []
        for g in groups:
            rest = [h for h in g.get("hooks", []) if not _is_ours(h)]
            if rest or not g.get("hooks"):
                kept.append({**g, "hooks": rest} if rest != g.get("hooks") else g)
        if kept:
            hooks[event] = kept
        else:
            del hooks[event]
    if not uninstall:
        for event, matcher in _EVENTS:
            handler: dict[str, Any] = {"type": "command", "command": python,
                                       "args": ["-m", "vipii", "guard"]}
            if event in _FAIL_CLOSED:
                handler["onFailure"] = "block"
            group: dict[str, Any] = {"hooks": [handler]}
            if matcher:
                group = {"matcher": matcher, **group}
            hooks.setdefault(event, []).append(group)
    if not hooks:
        del data["hooks"]

    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if text == raw:
        return "unchanged"
    settings.parent.mkdir(parents=True, exist_ok=True)
    if raw:
        settings.with_name(settings.name + ".vipii-bak").write_text(raw, encoding="utf-8")
    fd, tmp = tempfile.mkstemp(prefix=".vipii-", dir=settings.parent)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, settings)
    return "removed" if uninstall else "installed"


def default_settings(project: bool = False, env: Mapping[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    if project:
        return Path.cwd() / ".claude" / "settings.json"
    return Path(env.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude") / "settings.json"


def main(purge_state: bool = False) -> int:
    if purge_state:
        print(f"vipii guard: removed {purge()} mapping file(s)", file=sys.stderr)
        return 0
    code, out, err = run(sys.stdin.buffer.read().decode("utf-8", errors="replace"))
    if err:
        sys.stderr.write(err)
    if out:
        sys.stdout.write(out)
        sys.stdout.flush()
    return code
