"""vipii guard: Claude Code hooks that keep raw PII away from the model.

The model must only ever see masked text. Hooks run as separate processes, so the
placeholder mapping lives in a per-session file outside the project, and every failure
mode must end in "withheld", never in "original shown".
"""
import json
import os
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from vipii import guard

ROOT = Path(__file__).resolve().parents[1]
NAME, PHONE, EMAIL = "Nguyễn Văn An", "0912345678", "an.nguyen@congty.example"
RAW = f"Họ tên: {NAME}\nSĐT: {PHONE}\nEmail: {EMAIL}\n"


def ev(kind, **kw):
    return {"session_id": "sess-1", "cwd": "/tmp", "hook_event_name": kind, **kw}


def post(tool, response, state, tool_input=None):
    return guard.handle(ev("PostToolUse", tool_name=tool, tool_input=tool_input or {},
                           tool_response=response), state_dir=state)


def updated(out):
    return out["hookSpecificOutput"]["updatedToolOutput"]


def mapping(state, sid="sess-1"):
    return json.loads((Path(state) / f"{sid}.json").read_text(encoding="utf-8"))


@pytest.fixture
def state(tmp_path):
    return tmp_path / "guard"


# --------------------------------------------------------------- PostToolUse: masking

def test_read_output_is_masked_and_keeps_its_shape(state):
    resp = {"type": "text", "file": {"filePath": "/p/ho_so.txt", "content": RAW,
                                     "numLines": 4, "startLine": 1, "totalLines": 4}}
    out = updated(post("Read", resp, state))
    assert out["type"] == "text" and out["file"]["numLines"] == 4
    assert out["file"]["filePath"] == "/p/ho_so.txt"
    content = out["file"]["content"]
    for raw in (NAME, PHONE, EMAIL):
        assert raw not in content
    assert "<PERSON_1>" in content and "<PHONE_NUMBER_1>" in content


def test_bash_output_masks_stdout_and_stderr_but_keeps_flags(state):
    resp = {"stdout": RAW, "stderr": f"warn {PHONE}", "interrupted": False,
            "isImage": False, "noOutputExpected": False}
    out = updated(post("Bash", resp, state))
    assert PHONE not in out["stdout"] + out["stderr"]
    assert out["interrupted"] is False and out["isImage"] is False


def test_placeholders_are_stable_across_calls(state):
    a = updated(post("Bash", {"stdout": f"A {NAME}"}, state))["stdout"]
    b = updated(post("Bash", {"stdout": f"B {NAME} và {PHONE}"}, state))["stdout"]
    assert "<PERSON_1>" in a and "<PERSON_1>" in b and "<PHONE_NUMBER_1>" in b
    assert mapping(state)["<PERSON_1>"] == NAME


def test_mapping_file_is_private_and_outside_the_project(state):
    post("Bash", {"stdout": RAW}, state)
    path = state / "sess-1.json"
    assert path.exists()
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(state.stat().st_mode) == 0o700


def test_mcp_string_and_block_list_outputs_are_masked(state):
    assert PHONE not in updated(post("mcp__crm__lookup", f"tel {PHONE}", state))
    blocks = [{"type": "text", "text": f"{NAME} {PHONE}"}, {"type": "text", "text": "ok"}]
    out = updated(post("mcp__crm__lookup", blocks, state))
    assert NAME not in out[0]["text"] and out[1]["text"] == "ok"


def test_output_without_pii_is_left_alone(state):
    assert post("Bash", {"stdout": "hello", "stderr": "", "interrupted": False}, state) is None


@pytest.mark.parametrize("resp", [
    {"type": "image", "file": {"base64": "A" * 400, "type": "image/png"}},
    {"stdout": "x", "stderr": "", "interrupted": False, "isImage": True},
    {"type": "pdf", "file": {"base64": "JVBERi0" + "A" * 400}},
    [{"type": "image", "source": {"type": "base64", "data": "A" * 400}}],
])
def test_images_and_binary_outputs_are_withheld(state, resp):
    out = updated(post("Read", resp, state))
    flat = json.dumps(out)
    assert "AAAA" not in flat and "withheld" in flat


def test_every_string_leaf_is_masked_not_only_known_keys(state):
    resp = {"weird": {"nested": [f"x {PHONE}", {"deep": f"y {EMAIL}"}]}, "n": 3}
    out = json.dumps(updated(post("SomeNewTool", resp, state)), ensure_ascii=False)
    assert PHONE not in out and EMAIL not in out and '"n": 3' in out


# --------------------------------------------------------------- fail-closed

def test_masking_failure_withholds_instead_of_leaking(state, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("bug")
    monkeypatch.setattr(guard, "_mask_text", boom)
    resp = {"stdout": RAW, "stderr": "", "interrupted": False, "isImage": False}
    out = updated(post("Bash", resp, state))
    assert PHONE not in json.dumps(out) and "withheld" in out["stdout"]
    assert out["interrupted"] is False


def test_locked_state_that_never_frees_withholds(state, monkeypatch):
    state.mkdir(parents=True, mode=0o700)
    (state / "sess-1.json.lock").write_text("held")
    monkeypatch.setattr(guard, "LOCK_TIMEOUT", 0.3)
    out = updated(post("Bash", {"stdout": RAW}, state))
    assert PHONE not in json.dumps(out)


def test_corrupt_mapping_file_is_not_fatal_and_not_a_leak(state):
    state.mkdir(parents=True, mode=0o700)
    (state / "sess-1.json").write_text("{not json")
    out = updated(post("Bash", {"stdout": RAW}, state))
    assert PHONE not in out["stdout"]


def test_session_id_cannot_escape_the_state_dir(state):
    e = ev("PostToolUse", tool_name="Bash", tool_input={}, tool_response={"stdout": RAW})
    e["session_id"] = "../../evil"
    guard.handle(e, state_dir=state)
    files = [p for p in state.parent.rglob("*.json")]
    assert files and all(state in p.parents for p in files)


# --------------------------------------------------------------- PreToolUse

def seed(state):
    post("Bash", {"stdout": RAW}, state)  # creates <PERSON_1>, <PHONE_NUMBER_1>, <EMAIL_1>


def pre(tool, tool_input, state):
    return guard.handle(ev("PreToolUse", tool_name=tool, tool_input=tool_input), state_dir=state)


def test_edit_input_gets_real_values_back_and_keeps_other_fields(state):
    seed(state)
    inp = {"file_path": "/p/a.txt", "old_string": "Họ tên: <PERSON_1>",
           "new_string": "Họ tên: <PERSON_1> (KH)", "replace_all": False}
    out = pre("Edit", inp, state)["hookSpecificOutput"]
    assert out["hookEventName"] == "PreToolUse"
    new = out["updatedInput"]
    assert new["old_string"] == f"Họ tên: {NAME}" and f"{NAME} (KH)" in new["new_string"]
    assert new["file_path"] == "/p/a.txt" and new["replace_all"] is False
    assert "permissionDecision" not in out  # normal permission flow still applies


def test_write_and_bash_inputs_are_restored(state):
    seed(state)
    w = pre("Write", {"file_path": "/p/b.txt", "content": "call <PHONE_NUMBER_1>"}, state)
    assert w["hookSpecificOutput"]["updatedInput"]["content"] == f"call {PHONE}"
    b = pre("Bash", {"command": "grep -n '<EMAIL_1>' /p/b.txt"}, state)
    assert EMAIL in b["hookSpecificOutput"]["updatedInput"]["command"]


def test_input_without_placeholders_is_untouched(state):
    seed(state)
    assert pre("Bash", {"command": "ls -la"}, state) is None


def test_placeholders_unknown_to_this_session_are_not_invented(state):
    seed(state)
    assert pre("Bash", {"command": "echo <PERSON_9>"}, state) is None


@pytest.mark.parametrize("tool,inp", [
    ("Read", {"file_path": "{s}/sess-1.json"}),
    ("Bash", {"command": "cat {s}/sess-1.json"}),
    ("Bash", {"command": "cat ~/.vipii/guard/sess-1.json"}),
    ("Edit", {"file_path": "{s}/sess-1.json", "old_string": "a", "new_string": "b"}),
])
def test_the_agent_cannot_open_the_mapping_files(state, tool, inp):
    seed(state)
    inp = {k: v.replace("{s}", str(state)) for k, v in inp.items()}
    out = pre(tool, inp, state)["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert str(state) not in out["permissionDecisionReason"]


@pytest.mark.parametrize("name", ["scan.png", "CCCD.JPG", "hop_dong.pdf", "voice.mp3"])
def test_reading_images_pdfs_and_media_is_denied(state, name):
    out = pre("Read", {"file_path": f"/docs/{name}"}, state)["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny" and "anonymize" in out["permissionDecisionReason"]


def test_reading_plain_text_is_allowed(state):
    assert pre("Read", {"file_path": "/docs/ho_so.txt"}, state) is None


# --------------------------------------------------------------- UserPromptSubmit

def prompt(text, state, **env):
    return guard.handle(ev("UserPromptSubmit", prompt=text), state_dir=state, env=env)


def test_prompt_with_pii_is_blocked_and_shows_a_masked_copy(state):
    out = prompt(f"Soạn thư cho {NAME}, SĐT {PHONE}", state)
    assert out["decision"] == "block"
    assert out["hookSpecificOutput"]["suppressOriginalPrompt"] is True
    reason = out["reason"]
    assert NAME not in reason and PHONE not in reason
    assert "<PERSON_1>" in reason and "<PHONE_NUMBER_1>" in reason


def test_masked_copy_resent_later_restores_in_the_same_session(state):
    prompt(f"Gửi {NAME}", state)
    shown = guard.handle(ev("MessageDisplay", delta="Đã soạn thư cho <PERSON_1>.\n", index=0,
                            final=False), state_dir=state)
    assert NAME in shown["hookSpecificOutput"]["displayContent"]


def test_prompt_without_pii_passes(state):
    assert prompt("Viết hàm tính giai thừa", state) is None


def test_allow_marker_and_env_switches(state):
    assert prompt(f"{NAME} #allow-pii", state) is None
    assert prompt(f"{NAME}", state, VIPII_GUARD_PROMPT="off") is None
    assert prompt(f"{NAME}", state, VIPII_GUARD="off") is None
    assert prompt(f"{NAME}", state, VIPII_GUARD_PROMPT="block")["decision"] == "block"


# --------------------------------------------------------------- MessageDisplay

def test_display_restores_real_values_but_only_on_screen(state):
    seed(state)
    out = guard.handle(ev("MessageDisplay", delta="Gọi <PHONE_NUMBER_1> cho <PERSON_1>\n",
                          index=0, final=False), state_dir=state)
    shown = out["hookSpecificOutput"]["displayContent"]
    assert PHONE in shown and NAME in shown


def test_display_without_placeholders_changes_nothing(state):
    seed(state)
    assert guard.handle(ev("MessageDisplay", delta="xin chào\n", index=0, final=False),
                        state_dir=state) is None


# --------------------------------------------------------------- custom terms, misc

def test_custom_terms_from_env(state, tmp_path):
    terms = tmp_path / "projects.txt"
    terms.write_text("# secret\nProject Falcon\n", encoding="utf-8")
    e = ev("PostToolUse", tool_name="Bash", tool_input={},
           tool_response={"stdout": "ship Project Falcon tomorrow"})
    out = guard.handle(e, state_dir=state, env={"VIPII_GUARD_TERMS": f"PROJECT={terms}"})
    assert "Falcon" not in updated(out)["stdout"]


def test_unknown_event_and_disabled_guard_do_nothing(state):
    assert guard.handle(ev("SessionStart"), state_dir=state) is None
    e = ev("PostToolUse", tool_name="Bash", tool_input={}, tool_response={"stdout": RAW})
    assert guard.handle(e, state_dir=state, env={"VIPII_GUARD": "off"}) is None


def test_concurrent_hooks_do_not_lose_or_duplicate_placeholders(state):
    names = [f"Nguyễn Văn {c}" for c in "ABCDEFGHIJKLMNOP"]
    phones = [f"09{i:08d}" for i in range(16)]
    results = {}

    def work(i):
        r = post("Bash", {"stdout": f"Anh {names[i]}, SĐT {phones[i]}"}, state)
        results[i] = updated(r)["stdout"]

    threads = [threading.Thread(target=work, args=(i,)) for i in range(16)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    m = mapping(state)
    assert sorted(v for k, v in m.items() if k.startswith("<PHONE")) == sorted(phones)
    for i in range(16):  # each output restores to exactly its own input
        assert guard.deanonymize(results[i], m) == f"Anh {names[i]}, SĐT {phones[i]}"


def test_old_session_files_are_pruned(state):
    state.mkdir(parents=True, mode=0o700)
    old = state / "old.json"
    old.write_text("{}")
    os.utime(old, (1, 1))
    post("Bash", {"stdout": RAW}, state)
    assert not old.exists() and (state / "sess-1.json").exists()


# --------------------------------------------------------------- stdin/stdout protocol

def run_cli(payload, state, extra_env=None, args=()):
    env = {**os.environ, "VIPII_GUARD_DIR": str(state), "PYTHONIOENCODING": "utf-8"}
    env.update(extra_env or {})
    return subprocess.run([sys.executable, "-m", "vipii", "guard", *args], cwd=ROOT, env=env,
                          input=payload.encode("utf-8"), capture_output=True)


def test_cli_end_to_end_json_protocol(state):
    event = ev("PostToolUse", tool_name="Bash", tool_input={},
               tool_response={"stdout": RAW, "stderr": "", "interrupted": False})
    p = run_cli(json.dumps(event, ensure_ascii=False), state)
    assert p.returncode == 0
    out = json.loads(p.stdout.decode("utf-8"))
    assert out["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
    assert PHONE not in p.stdout.decode("utf-8")


def test_cli_silent_when_nothing_to_do(state):
    p = run_cli(json.dumps(ev("SessionStart")), state)
    assert p.returncode == 0 and p.stdout == b""


def test_cli_garbage_input_is_an_error_not_a_pass(state):
    p = run_cli("not json", state)
    assert p.returncode == 2 and b"Traceback" not in p.stderr


def test_cli_crash_in_masking_still_withholds(state, tmp_path):
    bad = tmp_path / "terms.txt"
    bad.write_bytes(b"\xff\xfe\x00")  # not UTF-8: terms cannot load
    event = ev("PostToolUse", tool_name="Bash", tool_input={},
               tool_response={"stdout": RAW, "stderr": "", "interrupted": False})
    p = run_cli(json.dumps(event, ensure_ascii=False), state,
                {"VIPII_GUARD_TERMS": f"X={bad}"})
    text = p.stdout.decode("utf-8")
    assert PHONE not in text and "withheld" in text


def test_cli_purge_removes_all_state(state):
    post("Bash", {"stdout": RAW}, state)
    p = run_cli("", state, args=("--purge",))
    assert p.returncode == 0 and not list(state.glob("*.json"))


# --------------------------------------------------------------- install into settings.json

def install(path, **kw):
    return guard.install(Path(path), python="/opt/py/bin/python", **kw)


def our_commands(settings):
    found = []
    for event, groups in settings.get("hooks", {}).items():
        for g in groups:
            for h in g["hooks"]:
                if h.get("args") == ["-m", "vipii", "guard"]:
                    found.append((event, g.get("matcher"), h))
    return found


def test_install_creates_all_four_hooks_fail_closed(tmp_path):
    p = tmp_path / ".claude" / "settings.json"
    install(p)
    cmds = our_commands(json.loads(p.read_text(encoding="utf-8")))
    assert sorted(e for e, _, _ in cmds) == ["MessageDisplay", "PostToolUse", "PreToolUse",
                                              "UserPromptSubmit"]
    by = {e: (m, h) for e, m, h in cmds}
    assert by["PostToolUse"][0] == "*" and by["PreToolUse"][0] == "*"
    for e in ("PostToolUse", "PreToolUse", "UserPromptSubmit"):
        assert by[e][1]["onFailure"] == "block"
    assert by["PostToolUse"][1]["command"] == "/opt/py/bin/python"


def test_install_keeps_existing_settings_and_is_idempotent(tmp_path):
    p = tmp_path / "settings.json"
    mine = {"type": "command", "command": "echo hi"}
    p.write_text(json.dumps({"model": "opus", "hooks": {"PostToolUse": [
        {"matcher": "Bash", "hooks": [mine]}]}}), encoding="utf-8")
    install(p)
    install(p)
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["model"] == "opus"
    assert {"matcher": "Bash", "hooks": [mine]} in data["hooks"]["PostToolUse"]
    assert len(our_commands(data)) == 4
    assert (tmp_path / "settings.json.vipii-bak").exists()


def test_uninstall_removes_only_our_hooks(tmp_path):
    p = tmp_path / "settings.json"
    other = {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo hi"}]}
    p.write_text(json.dumps({"hooks": {"PostToolUse": [other]}}), encoding="utf-8")
    install(p)
    install(p, uninstall=True)
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["hooks"] == {"PostToolUse": [other]}


def test_install_refuses_to_overwrite_an_unreadable_settings_file(tmp_path):
    p = tmp_path / "settings.json"
    p.write_text("{oops", encoding="utf-8")
    with pytest.raises(ValueError):
        install(p)
    assert p.read_text(encoding="utf-8") == "{oops"


def test_cli_install_and_uninstall(tmp_path):
    p = tmp_path / "s.json"
    r = subprocess.run([sys.executable, "-m", "vipii", "guard", "--install", "--settings", str(p)],
                       cwd=ROOT, capture_output=True)
    assert r.returncode == 0 and len(our_commands(json.loads(p.read_text()))) == 4
    assert {h["command"] for _, _, h in our_commands(json.loads(p.read_text()))} == {sys.executable}
    r = subprocess.run([sys.executable, "-m", "vipii", "guard", "--uninstall", "--settings",
                        str(p)], cwd=ROOT, capture_output=True)
    assert r.returncode == 0 and our_commands(json.loads(p.read_text())) == []
