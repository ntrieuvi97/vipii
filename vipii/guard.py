"""vipii guard: Claude Code and Antigravity hooks that keep raw PII away from the model.

A skill only *asks* the agent to mask data. These hooks *enforce* it at the tool layer:

Claude Code:
* ``PostToolUse``      masks every string in a tool result before the model sees it
  (``updatedToolOutput``): file reads, shell output, web fetches, MCP tools.
* ``PreToolUse``       turns placeholders in Edit/Write/Bash input back into real values
  so the agent can edit a masked file; denies reading the mapping files and image/PDF
  files that cannot be masked.
* ``UserPromptSubmit`` blocks a prompt that contains PII and shows a masked copy.
* ``MessageDisplay``   restores real values in what *you* read; the model keeps placeholders.

Antigravity (``PostToolUse`` cannot inspect or rewrite outputs, so ``PreToolUse`` enforces):
* ``PreToolUse``       masks files locally and overwrites ``Path``/``AbsolutePath`` on
  ``read_file``/``view_file``/outline tools; wraps ``run_command`` via ``vipii guard --exec``
  so stdout/stderr are masked; restores placeholders in write/edit/command inputs; denies
  ``grep_search``, mapping/config access, and binary/non-UTF-8 files.

Hooks are separate processes, so the placeholder mapping is a private per-session file.
Every failure path ends in "withheld" or "blocked", never in "original shown".
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import queue
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .anonymizer import anonymize, deanonymize
from .core import Analyzer
from .guard_config import GuardConfig, config_path, retry_os
from .guard_config import load as load_config

__all__ = ["antigravity_hooks_in", "deanonymize", "default_settings", "exec_command", "handle",
           "hooks_in", "install", "main", "purge", "run"]

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

AGY_READ_PATH_KEYS: dict[str, str] = {
    "read_file": "Path",
    "view_file": "AbsolutePath",
    "view_file_outline": "AbsolutePath",
    "view_code_item": "File",
}
AGY_RESTORE_FIELDS: dict[str, tuple[str, ...]] = {
    "write_file": ("Content",),
    "edit_file": ("Target", "Replacement"),
    "write_to_file": ("CodeContent",),
    "replace_file_content": ("TargetContent", "ReplacementContent"),
    "multi_replace_file_content": ("ReplacementChunks",),
    "manage_task": ("Input",),
    "send_command_input": ("Input",),
}
AGY_DENIED_TOOLS = {"grep_search"}
_AGY_PATH_KEYS = ("file_path", "Path", "AbsolutePath", "TargetFile", "File", "SearchPath")
_EXEC_BATCH_BYTES = 65536
_EXEC_BATCH_WAIT = 0.02


# ----------------------------------------------------------------------------- state

def _state_dir(explicit: str | Path | None, env: Mapping[str, str]) -> Path:
    if explicit is not None:
        return Path(explicit)
    return Path(env.get("VIPII_GUARD_DIR") or Path.home() / ".vipii" / "guard")


def _session_id(event: Mapping[str, Any]) -> str:
    raw = event.get("session_id") or event.get("conversationId") or "default"
    return re.sub(r"[^A-Za-z0-9_-]", "_", str(raw))[:80]


def _session_file(state: Path, event: Mapping[str, Any]) -> Path:
    return state / f"{_session_id(event)}.json"


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
    cache = state / "cache"
    if cache.is_dir():
        for p in cache.rglob("*"):
            try:
                if p.is_file() and p.stat().st_mtime < cutoff:
                    p.unlink()
            except OSError:
                pass
        for d in sorted((x for x in cache.rglob("*") if x.is_dir()), reverse=True):
            try:
                d.rmdir()
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


_retry_os = retry_os


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

def _analyzer(cfg: GuardConfig) -> Analyzer:
    if not cfg.terms:
        from . import _get_default
        return _get_default()
    from .cli import _terms
    return Analyzer(custom_terms=_terms([s for s in cfg.terms.split(";") if s]))


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


def _post(event: dict, state: Path, cfg: GuardConfig, env: Mapping[str, str]) -> dict | None:
    resp = event.get("tool_response")
    if resp is None:
        return None
    if _is_binary(resp):
        new = _withhold(resp)
    else:
        analyzer = _analyzer(cfg)
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


def _flat(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False).replace("\\\\", "/").lower()


def _event_cwd(event: Mapping[str, Any]) -> Path:
    raw = event.get("cwd")
    if isinstance(raw, str) and raw:
        return Path(raw)
    ws = event.get("workspacePaths")
    if isinstance(ws, list) and ws and isinstance(ws[0], str) and ws[0]:
        return Path(ws[0])
    return Path.cwd()


def _resolve_path(raw: str, event: Mapping[str, Any]) -> Path:
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = _event_cwd(event) / p
    return p


def _touches_state(tool_input: Any, state: Path, config: Path | None = None,
                   base_dir: Path | None = None) -> bool:
    flat = _flat(tool_input)
    protected = [str(state), str(config)] if config else [str(state)]
    if any(p.replace("\\", "/").lower() in flat for p in protected) or ".vipii/guard" in flat:
        return True
    if isinstance(tool_input, Mapping):
        try:
            state_res = state.resolve()
            cfg_res = config.resolve() if config else None
        except (OSError, ValueError, RuntimeError):
            return False
        for key in _AGY_PATH_KEYS:
            val = tool_input.get(key)
            if not isinstance(val, str) or not val.strip():
                continue
            try:
                p = Path(val).expanduser()
                if not p.is_absolute() and base_dir is not None:
                    p = base_dir / p
                res = p.resolve()
            except (OSError, ValueError, RuntimeError):
                continue
            if res == state_res or state_res in res.parents or (cfg_res and res == cfg_res):
                return True
    return False


_CONTROL = re.compile(r"(?:^|[\s;&|(`'\"/\\])vipii(?:\.exe)?\s+guard\b|-m\s+vipii\s+guard\b")
CONTROL_DENIED = ("vipii guard: its settings and stored mappings are not available to the agent. "
                  "To change a setting the user can run /vipii:guard <command> (or "
                  "`vipii guard <command>` in a terminal).")


def _deny(reason: str) -> dict:
    return _hook("PreToolUse", permissionDecision="deny", permissionDecisionReason=reason)


def _agy_deny(reason: str) -> dict[str, Any]:
    return {"decision": "deny", "reason": reason}


def _agy_overwrite(changes: dict[str, Any]) -> dict[str, Any]:
    return {"decision": "ask", "overwrite": changes}


def _is_antigravity(event: Mapping[str, Any]) -> bool:
    return "hookEventName" in event or "toolCall" in event or "conversationId" in event


def _write_masked_cache(state: Path, sid: str, target: Path, masked_text: str) -> Path:
    cache_root = state / "cache"
    cache_dir = cache_root / sid
    _ensure_dir(state)
    _ensure_dir(cache_root)
    _ensure_dir(cache_dir)
    digest = hashlib.sha256(f"{target}\n{masked_text}".encode()).hexdigest()[:16]
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", target.stem)[:40] or "file"
    suffix = target.suffix if re.fullmatch(r"\.[A-Za-z0-9]{1,10}", target.suffix) else ".txt"
    dest = cache_dir / f"{stem}_{digest}{suffix}"
    if dest.exists():
        return dest
    fd, tmp = tempfile.mkstemp(prefix=".vipii-", dir=cache_dir)  # mode 0600
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(masked_text)
        _retry_os(lambda: os.replace(tmp, dest))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return dest


def _wrap_command(cmd: str, sid: str, python: str | None = None) -> str:
    py = python or sys.executable
    if os.name == "nt":
        b64 = base64.b64encode(cmd.encode("utf-8")).decode("ascii")
        return subprocess.list2cmdline([py, "-m", "vipii", "guard", "--exec",
                                         "--session", sid, "--cmd-b64", b64])
    return (f"{shlex.quote(py)} -m vipii guard --exec"
            f" --session {shlex.quote(sid)} -- {shlex.quote(cmd)}")


def _pre_antigravity_read(tool: str, args: Mapping[str, Any], event: Mapping[str, Any],
                          state: Path, cfg: GuardConfig) -> dict[str, Any] | None:
    default_key = AGY_READ_PATH_KEYS[tool]
    path_key = next((k for k in (default_key, "Path", "AbsolutePath", "File")
                     if isinstance(args.get(k), str) and str(args[k]).strip()), None)
    if path_key is None:
        return None
    raw_path = str(args[path_key])
    if Path(raw_path).suffix.lower() in BINARY_SUFFIXES:
        return _agy_deny("vipii guard: images, PDFs and media cannot be masked. Convert them to "
                         "text, mask the text with `vipii anonymize`, and read that copy.")
    target = _resolve_path(raw_path, event)
    try:
        st = target.stat()
    except FileNotFoundError:
        return None
    if stat.S_ISDIR(st.st_mode):
        return None
    if not stat.S_ISREG(st.st_mode):
        return _agy_deny("vipii guard: special files cannot be masked.")
    raw_bytes = target.read_bytes()
    if b"\x00" in raw_bytes:
        return _agy_deny("vipii guard: binary files cannot be masked. Convert them to UTF-8 text "
                         "and mask with `vipii anonymize` first.")
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return _agy_deny("vipii guard: non-UTF-8 files cannot be masked. Convert them to UTF-8 "
                         "text and mask with `vipii anonymize` first.")
    analyzer = _analyzer(cfg)
    if not analyzer.analyze(text):
        return None
    if tool in {"read_file", "view_file"} and args.get("ByteOffset"):
        return _agy_deny("vipii guard: ByteOffset reads on files with PII are not supported "
                         "because masking changes byte offsets. Use StartLine and EndLine instead.")
    _ensure_dir(state)
    mapping_path = _session_file(state, event)
    with _Lock(mapping_path):
        mapping = _load(mapping_path)
        before = dict(mapping)
        masked = _mask_text(text, mapping, analyzer)
        if mapping != before:
            _save(mapping_path, mapping)
    _prune(state, keep=mapping_path)
    cache_file = _write_masked_cache(state, _session_id(event), target, masked)
    return _agy_overwrite({path_key: str(cache_file)})


def _pre_antigravity(event: dict, state: Path, cfg: GuardConfig,
                     env: Mapping[str, str]) -> dict[str, Any] | None:
    tool_call = event.get("toolCall")
    if not isinstance(tool_call, Mapping):
        return None
    tool = str(tool_call.get("name", ""))
    args = tool_call.get("args")
    if not isinstance(args, Mapping):
        return None
    if _touches_state(args, state, config_path(env), base_dir=_event_cwd(event)):
        return _agy_deny(CONTROL_DENIED)
    if tool in AGY_DENIED_TOOLS:
        return _agy_deny("vipii guard: grep_search is disabled in Antigravity because grep "
                         "output cannot be masked by hooks. Use read_file or run_command instead.")
    if tool == "run_command":
        cmd = str(args.get("CommandLine", ""))
        if _CONTROL.search(cmd):
            return _agy_deny(CONTROL_DENIED)
        if cfg.restore_edits:
            mapping = _load(_session_file(state, event))
            if mapping:
                cmd = deanonymize(cmd, mapping)
        return _agy_overwrite({"CommandLine": _wrap_command(cmd, _session_id(event))})
    if tool in AGY_READ_PATH_KEYS:
        return _pre_antigravity_read(tool, args, event, state, cfg)
    if tool in AGY_RESTORE_FIELDS and cfg.restore_edits:
        mapping = _load(_session_file(state, event))
        if not mapping:
            return None
        changes: dict[str, Any] = {}
        for field in AGY_RESTORE_FIELDS[tool]:
            if field in args:
                restored = _walk(args[field], lambda s: deanonymize(s, mapping))
                if restored != args[field]:
                    changes[field] = restored
        return _agy_overwrite(changes) if changes else None
    return None


def _pre(event: dict, state: Path, cfg: GuardConfig, env: Mapping[str, str]) -> dict | None:
    tool = str(event.get("tool_name", ""))
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    if _touches_state(tool_input, state, config_path(env)):
        return _deny(CONTROL_DENIED)
    if tool == "Bash" and _CONTROL.search(str(tool_input.get("command", ""))):
        return _deny(CONTROL_DENIED)
    suffix = Path(str(tool_input.get("file_path", ""))).suffix.lower()
    if tool == "Read" and suffix in BINARY_SUFFIXES:
        return _deny("vipii guard: images, PDFs and media cannot be masked. Convert them to "
                     "text, mask the text with `vipii anonymize`, and read that copy.")
    if tool not in RESTORE_TOOLS or not cfg.restore_edits:
        return None
    mapping = _load(_session_file(state, event))
    if not mapping:
        return None
    new = _walk(tool_input, lambda s: deanonymize(s, mapping))
    return None if new == tool_input else _hook("PreToolUse", updatedInput=new)


def _prompt(event: dict, state: Path, cfg: GuardConfig, env: Mapping[str, str]) -> dict | None:
    if cfg.prompt == "off":
        return None
    text = str(event.get("prompt", ""))
    if ALLOW_MARKER in text:
        return None
    analyzer = _analyzer(cfg)
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


def _display(event: dict, state: Path, cfg: GuardConfig, env: Mapping[str, str]) -> dict | None:
    delta = event.get("delta")
    if cfg.display != "restored" or not isinstance(delta, str) or not delta:
        return None  # default: the user sees the same masked text as the model
    mapping = _load(_session_file(state, event))
    if not mapping:
        return None
    shown = deanonymize(delta, mapping)
    return None if shown == delta else _hook("MessageDisplay", displayContent=shown)


def _failsafe(event: dict, kind: str, antigravity: bool = False) -> dict | None:
    """The guard itself broke: refuse, never pass the original through."""
    if antigravity:
        if kind == "PreToolUse":
            return _agy_deny("vipii guard failed (fail-closed). Set VIPII_GUARD=off to disable it.")
        return None
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


_HANDLERS: dict[str, Callable[..., dict | None]] = {
    "PostToolUse": _post, "PreToolUse": _pre, "UserPromptSubmit": _prompt,
    "MessageDisplay": _display,
}


def handle(event: dict, state_dir: str | Path | None = None,
           env: Mapping[str, str] | None = None) -> dict | None:
    """Map one hook event to the JSON the hook must print (None = print nothing)."""
    env = os.environ if env is None else env
    is_agy = _is_antigravity(event)
    kind = str(event.get("hook_event_name") or event.get("hookEventName") or "")
    if not kind and is_agy and isinstance(event.get("toolCall"), Mapping) and "error" not in event:
        kind = "PreToolUse"
    fn: Callable[..., dict | None] | None
    if is_agy:
        fn = _pre_antigravity if kind == "PreToolUse" else None
    else:
        fn = _HANDLERS.get(kind)
    if fn is None:
        return None
    try:
        cfg = load_config(env)
        if not cfg.enabled:
            return None
        return fn(event, _state_dir(state_dir, env), cfg, env)
    except Exception:
        return _failsafe(event, kind, antigravity=is_agy)


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


def _mask_exec_chunk(text: str, analyzer: Analyzer, state: Path, mapping_path: Path) -> str:
    if not text.strip() or not analyzer.analyze(text):
        return text
    _ensure_dir(state)
    with _Lock(mapping_path):
        mapping = _load(mapping_path)
        before = dict(mapping)
        masked = _mask_text(text, mapping, analyzer)
        if mapping != before:
            _save(mapping_path, mapping)
    _prune(state, keep=mapping_path)
    return masked


def exec_command(command: str, session_id: str = "default",
                 state_dir: str | Path | None = None,
                 env: Mapping[str, str] | None = None,
                 stdout: Any = None, stderr: Any = None) -> int:
    """Run one shell command and mask its stdout/stderr before Antigravity sees them."""
    env = os.environ if env is None else env
    out_stream = stdout or sys.stdout.buffer
    err_stream = stderr or sys.stderr.buffer
    cfg = load_config(env)
    if not cfg.enabled:
        return subprocess.run(command, shell=True).returncode
    try:
        analyzer = _analyzer(cfg)
    except Exception:
        err_stream.write((WITHHELD + "\n").encode("utf-8"))
        err_stream.flush()
        return 2
    state = _state_dir(state_dir, env)
    mapping_path = _session_file(state, {"session_id": session_id})
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            bufsize=0)
    assert proc.stdout is not None and proc.stderr is not None
    q: queue.Queue[tuple[str, bytes | None]] = queue.Queue()

    def _pump(name: str, pipe: Any) -> None:
        try:
            for chunk in iter(pipe.readline, b""):
                q.put((name, chunk))
        finally:
            q.put((name, None))

    threads = [
        threading.Thread(target=_pump, args=("stdout", proc.stdout), daemon=True),
        threading.Thread(target=_pump, args=("stderr", proc.stderr), daemon=True),
    ]
    for t in threads:
        t.start()

    bufs: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    tainted: dict[str, bool] = {"stdout": False, "stderr": False}
    streams = {"stdout": out_stream, "stderr": err_stream}
    done: set[str] = set()

    def _flush(name: str) -> None:
        buf = bufs[name]
        if not buf:
            return
        raw = bytes(buf)
        buf.clear()
        target = streams[name]
        if tainted[name]:
            return
        if b"\x00" in raw:
            tainted[name] = True
            target.write((WITHHELD + "\n").encode("utf-8"))
            target.flush()
            return
        try:
            text = raw.decode("utf-8")
            masked = _mask_exec_chunk(text, analyzer, state, mapping_path)
            target.write(masked.encode("utf-8"))
        except UnicodeDecodeError:
            tainted[name] = True
            target.write((WITHHELD + "\n").encode("utf-8"))
        except Exception:
            target.write((WITHHELD + "\n").encode("utf-8"))
        target.flush()

    while len(done) < 2:
        try:
            name, chunk = q.get(timeout=_EXEC_BATCH_WAIT)
        except queue.Empty:
            _flush("stdout")
            _flush("stderr")
            continue
        if chunk is None:
            done.add(name)
            _flush(name)
            continue
        bufs[name].extend(chunk)
        if len(bufs[name]) >= _EXEC_BATCH_BYTES:
            _flush(name)

    for t in threads:
        t.join()
    return proc.wait()


def purge(state_dir: str | Path | None = None, env: Mapping[str, str] | None = None) -> int:
    """Delete every stored mapping and masked cache file. Returns the number of files removed."""
    state = _state_dir(state_dir, os.environ if env is None else env)
    count = 0
    for pattern in ("*.json", "*.lock", "*.corrupt-*"):
        for p in state.glob(pattern):
            try:
                p.unlink()
                count += 1
            except OSError:
                pass
    cache = state / "cache"
    if cache.is_dir():
        count += sum(1 for p in cache.rglob("*") if p.is_file())
        shutil.rmtree(cache, ignore_errors=True)
    return count


_FAIL_CLOSED = {"PostToolUse", "PreToolUse", "UserPromptSubmit"}
_EVENTS = [("PreToolUse", "*"), ("PostToolUse", "*"), ("UserPromptSubmit", None)]


def _is_ours(handler: Mapping[str, Any]) -> bool:
    return handler.get("args") == ["-m", "vipii", "guard"]


def install(settings: Path, python: str | None = None, uninstall: bool = False,
            restored_display: bool = False) -> str:
    """Add (or remove) the guard hooks in a Claude Code ``settings.json``.

    Other settings and hooks are kept, the file is replaced atomically, the previous
    version is saved as ``settings.json.vipii-bak``, and running it twice changes nothing.
    The interpreter is stored as an absolute path, so hooks do not depend on ``PATH``.
    The ``MessageDisplay`` hook (real values on the user's screen) is only registered when
    ``restored_display`` is set; by default the user sees the same masked text as the model.
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
        events = [*_EVENTS, *([("MessageDisplay", None)] if restored_display else [])]
        for event, matcher in events:
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
    if project:
        return Path.cwd() / ".claude" / "settings.json"
    for source in (env or {}, os.environ):
        if source.get("CLAUDE_CONFIG_DIR"):
            return Path(source["CLAUDE_CONFIG_DIR"]) / "settings.json"
    return Path.home() / ".claude" / "settings.json"


def hooks_in(settings: Path) -> list[str]:
    """Events for which ``settings`` contains a vipii guard hook (empty if none/unreadable)."""
    try:
        hooks = json.loads(settings.read_text(encoding="utf-8")).get("hooks", {})
        return sorted(e for e, groups in hooks.items()
                      if any(_is_ours(h) for g in groups for h in g.get("hooks", [])))
    except (OSError, ValueError, AttributeError):
        return []


_AGY_GROUPED_EVENTS = ("PreToolUse", "PostToolUse")
_AGY_FLAT_EVENTS = ("PreInvocation", "PostInvocation", "SessionStart", "Stop")


def antigravity_hooks_in(hooks_file: Path) -> list[str]:
    """Events for which an Antigravity ``hooks.json`` contains an enabled vipii guard hook."""
    try:
        data = json.loads(hooks_file.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return []
        found: set[str] = set()
        for spec in data.values():
            if not isinstance(spec, dict) or spec.get("enabled") is False:
                continue
            for event in _AGY_GROUPED_EVENTS:
                groups = spec.get(event)
                if isinstance(groups, list) and any(
                    isinstance(h, dict) and _CONTROL.search(str(h.get("command", "")))
                    for g in groups if isinstance(g, dict)
                    for h in g.get("hooks", []) if isinstance(g.get("hooks"), list)
                ):
                    found.add(event)
            for event in _AGY_FLAT_EVENTS:
                handlers = spec.get(event)
                if isinstance(handlers, list) and any(
                    isinstance(h, dict) and _CONTROL.search(str(h.get("command", "")))
                    for h in handlers
                ):
                    found.add(event)
        return sorted(found)
    except (OSError, ValueError, AttributeError, TypeError):
        return []


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
