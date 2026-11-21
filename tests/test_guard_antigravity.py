"""vipii guard: Antigravity PreToolUse hooks and --exec wrapper."""
import base64
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from vipii import guard, guard_config, guard_ctl

ROOT = Path(__file__).resolve().parents[1]
NAME, PHONE, EMAIL = "Nguyễn Văn An", "0912345678", "an.nguyen@congty.example"
RAW = f"Họ tên: {NAME}\nSĐT: {PHONE}\nEmail: {EMAIL}\n"


def agy_ev(kind="PreToolUse", tool=None, args=None, sid="conv-1", cwd="/tmp"):
    payload = {
        "conversationId": sid,
        "cwd": str(cwd),
        "hookEventName": kind,
        "workspacePaths": [str(cwd)],
    }
    if tool is not None:
        payload["toolCall"] = {"name": tool, "args": args or {}}
    return payload


def pre(tool, args, state, sid="conv-1", cwd="/tmp", env=None):
    return guard.handle(agy_ev("PreToolUse", tool=tool, args=args, sid=sid, cwd=cwd),
                        state_dir=state, env=env)


def mapping(state, sid="conv-1"):
    return json.loads((Path(state) / f"{sid}.json").read_text(encoding="utf-8"))


@pytest.fixture
def state(tmp_path):
    return tmp_path / "guard"


# --------------------------------------------------------------- file reads

@pytest.mark.parametrize("tool,key", [
    ("read_file", "Path"),
    ("view_file", "AbsolutePath"),
    ("view_file_outline", "AbsolutePath"),
    ("view_code_item", "File"),
])
def test_read_tools_mask_and_overwrite_to_cache(tmp_path, state, tool, key):
    doc = tmp_path / "ho_so.txt"
    doc.write_text(RAW, encoding="utf-8")

    out = pre(tool, {key: str(doc)}, state)
    assert out["decision"] == "ask"
    cached = Path(out["overwrite"][key])
    assert cached != doc and state in cached.parents
    masked = cached.read_text(encoding="utf-8")
    for raw in (NAME, PHONE, EMAIL):
        assert raw not in masked
    assert "<PERSON_1>" in masked and "<PHONE_NUMBER_1>" in masked
    assert doc.read_text(encoding="utf-8") == RAW  # original file untouched
    assert mapping(state)["<PERSON_1>"] == NAME
    if os.name == "posix":
        assert stat.S_IMODE(cached.stat().st_mode) == 0o600


def test_read_file_resolves_relative_path_against_event_cwd(tmp_path, state):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "kh.txt").write_text(f"SĐT: {PHONE}\n", encoding="utf-8")

    out = pre("read_file", {"Path": "kh.txt"}, state, cwd=proj)
    cached = Path(out["overwrite"]["Path"])
    assert "<PHONE_NUMBER_1>" in cached.read_text(encoding="utf-8")


def test_read_file_without_pii_is_untouched(tmp_path, state):
    doc = tmp_path / "code.py"
    doc.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    assert pre("read_file", {"Path": str(doc)}, state) is None
    assert not (state / "cache").exists()


def test_read_file_missing_or_directory_passes_through(tmp_path, state):
    assert pre("read_file", {"Path": str(tmp_path / "nope.txt")}, state) is None
    assert pre("read_file", {"Path": str(tmp_path)}, state) is None


@pytest.mark.parametrize("name", ["scan.png", "CCCD.JPG", "hop_dong.pdf", "voice.mp3"])
def test_read_tools_deny_binary_suffixes(state, name):
    out = pre("read_file", {"Path": f"/docs/{name}"}, state)
    assert out["decision"] == "deny" and "anonymize" in out["reason"]


@pytest.mark.parametrize("payload", [b"\x89PNG\r\n\x1a\n\x00\x00", b"\xff\xfe\x00\x00invalid"])
def test_read_tools_deny_binary_or_non_utf8_content(tmp_path, state, payload):
    blob = tmp_path / "data.dat"
    blob.write_bytes(payload)
    out = pre("read_file", {"Path": str(blob)}, state)
    assert out["decision"] == "deny"


def test_read_file_byte_offset_is_denied_only_when_pii_present(tmp_path, state):
    clean = tmp_path / "clean.txt"
    clean.write_text("hello world\n", encoding="utf-8")
    assert pre("read_file", {"Path": str(clean), "ByteOffset": 5}, state) is None

    pii = tmp_path / "pii.txt"
    pii.write_text(RAW, encoding="utf-8")
    out = pre("read_file", {"Path": str(pii), "ByteOffset": 10}, state)
    assert out["decision"] == "deny" and "StartLine" in out["reason"]


# --------------------------------------------------------------- grep_search & security boundaries

def test_grep_search_is_denied(state):
    out = pre("grep_search", {"Query": "0912", "SearchPath": "/tmp"}, state)
    assert out["decision"] == "deny" and "read_file" in out["reason"]


def test_symlink_to_mapping_file_is_denied(tmp_path, state):
    doc = tmp_path / "pii.txt"
    doc.write_text(RAW, encoding="utf-8")
    pre("read_file", {"Path": str(doc)}, state)
    link = tmp_path / "innocent.txt"
    try:
        link.symlink_to(state / "conv-1.json")
    except OSError:
        pytest.skip("symlinks not supported")
    out = pre("read_file", {"Path": str(link)}, state)
    assert out["decision"] == "deny"


def test_antigravity_cannot_run_guard_commands_or_touch_config(state):
    cfg = guard_config.config_path()
    for tool, args in [
        ("run_command", {"CommandLine": "vipii guard disable"}),
        ("run_command", {"CommandLine": "python3 -m vipii guard status"}),
        ("read_file", {"Path": str(cfg)}),
        ("write_file", {"Path": str(state / "conv-1.json"), "Content": "{}"}),
    ]:
        out = pre(tool, args, state)
        assert out["decision"] == "deny"


def test_conversation_id_cannot_escape_state_dir(tmp_path, state):
    doc = tmp_path / "pii.txt"
    doc.write_text(RAW, encoding="utf-8")
    out = pre("read_file", {"Path": str(doc)}, state, sid="../../evil")
    cached = Path(out["overwrite"]["Path"])
    assert state in cached.parents
    assert all(state in p.parents for p in state.parent.rglob("*.json"))


# --------------------------------------------------------------- write/edit restoration

@pytest.mark.parametrize("tool,args,expected", [
    ("write_file", {"Path": "/p/a.txt", "Content": "Call <PHONE_NUMBER_1>"},
     {"Content": f"Call {PHONE}"}),
    ("edit_file", {"Path": "/p/a.txt", "Target": "Họ tên: <PERSON_1>",
                   "Replacement": "Họ tên: <PERSON_1> (VIP)"},
     {"Target": f"Họ tên: {NAME}", "Replacement": f"Họ tên: {NAME} (VIP)"}),
    ("write_to_file", {"TargetFile": "/p/a.txt", "CodeContent": "<EMAIL_1>"},
     {"CodeContent": EMAIL}),
    ("replace_file_content", {"TargetFile": "/p/a.txt", "TargetContent": "<PERSON_1>",
                              "ReplacementContent": "<PERSON_1> <PHONE_NUMBER_1>"},
     {"TargetContent": NAME, "ReplacementContent": f"{NAME} {PHONE}"}),
    ("multi_replace_file_content",
     {"TargetFile": "/p/a.txt",
      "ReplacementChunks": [{"TargetContent": "<PERSON_1>", "ReplacementContent": "<EMAIL_1>"}]},
     {"ReplacementChunks": [{"TargetContent": NAME, "ReplacementContent": EMAIL}]}),
    ("manage_task", {"Action": "send_input", "TaskId": "t1", "Input": "<PHONE_NUMBER_1>\n"},
     {"Input": f"{PHONE}\n"}),
    ("send_command_input", {"CommandId": "c1", "Input": "<PERSON_1>\n"},
     {"Input": f"{NAME}\n"}),
])
def test_write_and_edit_tools_restore_placeholders(tmp_path, state, tool, args, expected):
    doc = tmp_path / "pii.txt"
    doc.write_text(RAW, encoding="utf-8")
    pre("read_file", {"Path": str(doc)}, state)

    out = pre(tool, args, state)
    assert out == {"decision": "ask", "overwrite": expected}


def test_restore_edits_off_leaves_write_tools_untouched(tmp_path, state):
    doc = tmp_path / "pii.txt"
    doc.write_text(RAW, encoding="utf-8")
    pre("read_file", {"Path": str(doc)}, state)
    guard_config.set_value("restore_edits", "off")
    assert pre("write_file", {"Path": "/p/a.txt", "Content": "<PERSON_1>"}, state) is None


# --------------------------------------------------------------- run_command & --exec

def test_run_command_is_wrapped_and_restored_end_to_end(tmp_path, state):
    doc = tmp_path / "pii.txt"
    doc.write_text(RAW, encoding="utf-8")
    pre("read_file", {"Path": str(doc)}, state)

    cmd = "echo \"<PERSON_1>\" && echo \"err <PHONE_NUMBER_1>\" >&2"
    if os.name == "nt":
        cmd = "echo <PERSON_1> & echo err <PHONE_NUMBER_1> 1>&2"
    out = pre("run_command", {"CommandLine": cmd}, state)
    assert out["decision"] == "ask"
    wrapped = out["overwrite"]["CommandLine"]
    assert "--exec" in wrapped and NAME in wrapped  # restored before exec

    env = {**os.environ, "VIPII_GUARD_DIR": str(state), "PYTHONIOENCODING": "utf-8"}
    res = subprocess.run(wrapped, shell=True, cwd=ROOT, env=env, capture_output=True)
    assert res.returncode == 0
    stdout = res.stdout.decode("utf-8")
    stderr = res.stderr.decode("utf-8")
    assert NAME not in stdout and "<PERSON_1>" in stdout
    assert PHONE not in stderr and "<PHONE_NUMBER_1>" in stderr


def test_exec_preserves_exit_code_multiline_context_and_env_tamper_resistance(tmp_path, state):
    env = {**os.environ, "VIPII_GUARD_DIR": str(state), "PYTHONIOENCODING": "utf-8"}
    script = tmp_path / "emit.py"
    script.write_text(
        "import sys\n"
        "print('MST\\n0300588569')\n"
        "sys.exit(7)\n",
        encoding="utf-8",
    )
    out = pre("run_command", {"CommandLine": f"VIPII_GUARD=off {sys.executable} {script}"}, state)
    wrapped = out["overwrite"]["CommandLine"]
    res = subprocess.run(wrapped, shell=True, cwd=ROOT, env=env, capture_output=True)
    assert res.returncode == 7
    text = res.stdout.decode("utf-8")
    assert "0300588569" not in text and "<TAX_CODE_1>" in text


def test_exec_withholds_binary_stdout(tmp_path, state):
    env = {**os.environ, "VIPII_GUARD_DIR": str(state)}
    script = tmp_path / "bin.py"
    script.write_text("import sys; sys.stdout.buffer.write(b'\\x00\\xff\\xfesecret')",
                      encoding="utf-8")
    b64 = base64.b64encode(f"{sys.executable} {script}".encode()).decode("ascii")
    res = subprocess.run([sys.executable, "-m", "vipii", "guard", "--exec",
                          "--session", "conv-1", "--cmd-b64", b64],
                         cwd=ROOT, env=env, capture_output=True)
    assert res.returncode == 0
    assert b"secret" not in res.stdout and b"withheld" in res.stdout


# --------------------------------------------------------------- lifecycle, fail-closed, purge, status

def test_antigravity_fail_closed_and_disabled_and_non_pre_events(tmp_path, state, monkeypatch):
    doc = tmp_path / "pii.txt"
    doc.write_text(RAW, encoding="utf-8")

    monkeypatch.setattr(guard, "_pre_antigravity", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    err = pre("read_file", {"Path": str(doc)}, state)
    assert err["decision"] == "deny" and "fail-closed" in err["reason"]

    monkeypatch.undo()
    assert guard.handle(agy_ev("PostToolUse", tool="read_file", args={"Path": str(doc)}),
                        state_dir=state) is None
    assert pre("read_file", {"Path": str(doc)}, state, env={"VIPII_GUARD": "off"}) is None


def test_purge_and_prune_remove_cached_masked_files(tmp_path, state):
    doc = tmp_path / "pii.txt"
    doc.write_text(RAW, encoding="utf-8")
    out = pre("read_file", {"Path": str(doc)}, state)
    cached = Path(out["overwrite"]["Path"])
    assert cached.exists()
    os.utime(cached, (1, 1))
    guard._prune(state, keep=state / "conv-1.json")
    assert not cached.exists()

    pre("read_file", {"Path": str(doc)}, state)
    assert guard.purge(state_dir=state) >= 2
    assert not (state / "cache").exists()


def test_bundled_hooks_json_and_status_detection(tmp_path, monkeypatch):
    hooks_file = ROOT / "hooks.json"
    assert hooks_file.exists()
    assert guard.antigravity_hooks_in(hooks_file) == ["PreToolUse"]

    agy_project = tmp_path / ".agents" / "hooks.json"
    agy_project.parent.mkdir(parents=True)
    agy_project.write_text(hooks_file.read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    code, text = guard_ctl.run(["status"])
    assert code == 0 and "antigravity project" in text and str(agy_project) in text
