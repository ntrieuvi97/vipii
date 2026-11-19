"""vipii guard: configuration file, control commands and what they change in the hooks."""
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from vipii import guard, guard_config, guard_ctl

ROOT = Path(__file__).resolve().parents[1]
NAME, PHONE = "Nguyễn Văn An", "0912345678"


def ev(kind, **kw):
    return {"session_id": "s1", "cwd": "/tmp", "hook_event_name": kind, **kw}


def ctl(*words, env=None):
    return guard_ctl.run(list(words), env=env)


def cfg_path():
    return Path(os.environ["VIPII_GUARD_CONFIG"])


# ------------------------------------------------------------------ defaults and storage

def test_defaults_are_mask_only():
    c = guard_config.load({})
    assert (c.enabled, c.prompt, c.display, c.restore_edits, c.terms) == (
        True, "block", "masked", True, "")


def test_set_persists_privately_and_survives_reload():
    guard_config.set_value("display", "restored")
    assert guard_config.load({}).display == "restored"
    if os.name == "posix":
        assert stat.S_IMODE(cfg_path().stat().st_mode) == 0o600
        assert stat.S_IMODE(cfg_path().parent.stat().st_mode) == 0o700
    assert json.loads(cfg_path().read_text(encoding="utf-8")) == {"display": "restored"}


@pytest.mark.parametrize("key,value", [("display", "loud"), ("prompt", "maybe"), ("enabled", "perhaps"),
                                       ("restore_edits", "2"), ("nope", "x")])
def test_invalid_keys_and_values_are_rejected_without_writing(key, value):
    with pytest.raises(ValueError):
        guard_config.set_value(key, value)
    assert not cfg_path().exists()


@pytest.mark.parametrize("raw,expected", [("on", True), ("TRUE", True), ("yes", True), ("1", True),
                                          ("off", False), ("false", False), ("no", False), ("0", False)])
def test_booleans_accept_the_usual_spellings(raw, expected):
    guard_config.set_value("enabled", raw)
    assert guard_config.load({}).enabled is expected


def test_environment_beats_the_file():
    guard_config.set_value("prompt", "off")
    guard_config.set_value("display", "masked")
    c = guard_config.load({"VIPII_GUARD_PROMPT": "block", "VIPII_GUARD_DISPLAY": "restored",
                           "VIPII_GUARD": "off", "VIPII_GUARD_RESTORE_EDITS": "off",
                           "VIPII_GUARD_TERMS": "X=/t.txt"})
    assert (c.prompt, c.display, c.enabled, c.restore_edits, c.terms) == (
        "block", "restored", False, False, "X=/t.txt")


def test_corrupt_config_falls_back_to_safe_defaults_not_to_off():
    cfg_path().parent.mkdir(parents=True)
    cfg_path().write_text("{broken", encoding="utf-8")
    c = guard_config.load({})
    assert c.enabled is True and c.prompt == "block" and c.display == "masked"


def test_unknown_keys_in_the_file_are_ignored():
    cfg_path().parent.mkdir(parents=True)
    cfg_path().write_text(json.dumps({"display": "restored", "future": 1}), encoding="utf-8")
    assert guard_config.load({}).display == "restored"


def test_reset_removes_the_file():
    guard_config.set_value("prompt", "off")
    guard_config.reset()
    assert not cfg_path().exists() and guard_config.load({}).prompt == "block"


# ------------------------------------------------------------------ the hooks obey the config

def post(state, text):
    return guard.handle(ev("PostToolUse", tool_name="Bash", tool_input={},
                           tool_response={"stdout": text}), state_dir=state)


def test_disabled_guard_touches_nothing(tmp_path):
    guard_config.set_value("enabled", "off")
    assert post(tmp_path / "st", f"{NAME} {PHONE}") is None
    assert guard.handle(ev("UserPromptSubmit", prompt=NAME), state_dir=tmp_path / "st") is None


def test_prompt_setting_off_lets_prompts_through(tmp_path):
    st = tmp_path / "st"
    assert guard.handle(ev("UserPromptSubmit", prompt=NAME), state_dir=st)["decision"] == "block"
    guard_config.set_value("prompt", "off")
    assert guard.handle(ev("UserPromptSubmit", prompt=NAME), state_dir=st) is None


def test_masking_of_tool_output_stays_on_when_the_prompt_check_is_off(tmp_path):
    guard_config.set_value("prompt", "off")
    out = post(tmp_path / "st", f"Anh {NAME}")["hookSpecificOutput"]["updatedToolOutput"]
    assert NAME not in out["stdout"]


def test_display_is_masked_by_default_and_restored_only_on_request(tmp_path):
    st = tmp_path / "st"
    post(st, f"Anh {NAME}")
    def shown():
        return guard.handle(ev("MessageDisplay", delta="Gọi <PERSON_1>\n", index=0, final=False),
                            state_dir=st)

    assert shown() is None                       # default: the user also sees the placeholder
    guard_config.set_value("display", "restored")
    assert NAME in shown()["hookSpecificOutput"]["displayContent"]


def test_restore_edits_can_be_turned_off(tmp_path):
    st = tmp_path / "st"
    post(st, f"Anh {NAME}")
    edit = ev("PreToolUse", tool_name="Edit",
              tool_input={"file_path": "/p/a", "old_string": "<PERSON_1>", "new_string": "x"})
    assert guard.handle(edit, state_dir=st)["hookSpecificOutput"]["updatedInput"]["old_string"] == NAME
    guard_config.set_value("restore_edits", "off")
    assert guard.handle(edit, state_dir=st) is None


def test_terms_from_the_config_file(tmp_path):
    terms = tmp_path / "t.txt"
    terms.write_text("Project Falcon\n", encoding="utf-8")
    guard_config.set_value("terms", f"PROJECT={terms}")
    out = post(tmp_path / "st", "ship Project Falcon")["hookSpecificOutput"]["updatedToolOutput"]
    assert "Falcon" not in out["stdout"]


# ------------------------------------------------------------------ the agent cannot reconfigure the guard

@pytest.mark.parametrize("command", [
    "vipii guard disable", "vipii guard config enabled off", "/home/u/.local/bin/vipii guard --uninstall",
    "python3 -m vipii guard purge", "cd /tmp && vipii guard prompt off", "sudo vipii guard display restored",
    "VIPII_GUARD=off vipii guard install", "echo hi; vipii guard ctl disable",
    "cat ~/.vipii/guard-config.json", "echo '{}' > ~/.vipii/guard-config.json",
])
def test_the_agent_cannot_run_control_commands_or_touch_the_config(tmp_path, command):
    e = ev("PreToolUse", tool_name="Bash", tool_input={"command": command})
    out = guard.handle(e, state_dir=tmp_path / "st")["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "/vipii:guard" in out["permissionDecisionReason"]


def test_the_agent_cannot_edit_the_config_file_with_other_tools(tmp_path):
    e = ev("PreToolUse", tool_name="Write", tool_input={"file_path": str(cfg_path()), "content": "{}"})
    assert guard.handle(e, state_dir=tmp_path / "st")["hookSpecificOutput"][
        "permissionDecision"] == "deny"


@pytest.mark.parametrize("command", [
    "vipii anonymize doc.txt --map ~/.vipii/session.json", "vipii analyze doc.txt",
    "pip show vipii", "echo guard the door", "ls ~/.vipii",
])
def test_ordinary_vipii_use_is_not_blocked(tmp_path, command):
    e = ev("PreToolUse", tool_name="Bash", tool_input={"command": command})
    assert guard.handle(e, state_dir=tmp_path / "st") is None


# ------------------------------------------------------------------ control commands (what /vipii:guard runs)

def test_status_reports_effective_settings_and_hooks():
    code, text = ctl("status")
    assert code == 0
    for needle in ("enabled: on", "prompt: block", "display: masked", "restore-edits: on",
                   "hooks: not installed"):
        assert needle in text, text


def test_no_words_means_status():
    assert ctl()[1] == ctl("status")[1]
    assert ctl("ctl")[1] == ctl("status")[1]  # the slash command always passes the word ctl


def test_shorthand_and_config_forms_change_the_same_setting():
    assert ctl("disable")[0] == 0 and guard_config.load({}).enabled is False
    assert ctl("enable")[0] == 0 and guard_config.load({}).enabled is True
    assert ctl("prompt", "off")[0] == 0 and guard_config.load({}).prompt == "off"
    assert ctl("config", "prompt", "block")[0] == 0 and guard_config.load({}).prompt == "block"
    assert ctl("restore-edits", "off")[0] == 0 and guard_config.load({}).restore_edits is False
    assert ctl("config", "restore_edits", "on")[0] == 0 and guard_config.load({}).restore_edits is True


def test_config_without_value_shows_the_current_value():
    ctl("display", "restored")
    assert "restored" in ctl("config", "display")[1]
    assert "display" in ctl("config")[1]


def test_bad_input_is_a_clean_error():
    for words in (["display", "loud"], ["prompt"], ["frobnicate"], ["config", "nope", "x"]):
        code, text = ctl(*words)
        assert code == 2 and "Traceback" not in text and "usage" in text.lower(), words


def test_terms_command_sets_shows_and_clears():
    assert ctl("terms", "PROJECT=/x.txt")[0] == 0
    assert "PROJECT=/x.txt" in ctl("terms")[1]
    assert ctl("terms", "clear")[0] == 0 and guard_config.load({}).terms == ""


def test_status_says_when_an_environment_variable_overrides_the_file():
    ctl("prompt", "block")
    _, text = ctl("status", env={"VIPII_GUARD_PROMPT": "off"})
    assert "prompt: off" in text and "VIPII_GUARD_PROMPT" in text


def test_reset_command():
    ctl("prompt", "off")
    assert ctl("reset")[0] == 0 and guard_config.load({}).prompt == "block"


# ------------------------------------------------------------------ settings.json follows the display setting

def user_settings():
    return Path(os.environ["CLAUDE_CONFIG_DIR"]) / "settings.json"


def events_of(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    return sorted(e for e, groups in data.get("hooks", {}).items()
                  if any(h.get("args") == ["-m", "vipii", "guard"] for g in groups for h in g["hooks"]))


def test_install_registers_display_hook_only_when_restoring():
    assert ctl("install")[0] == 0
    assert events_of(user_settings()) == ["PostToolUse", "PreToolUse", "UserPromptSubmit"]
    ctl("display", "restored")
    assert events_of(user_settings()) == ["MessageDisplay", "PostToolUse", "PreToolUse",
                                          "UserPromptSubmit"]
    ctl("display", "masked")
    assert events_of(user_settings()) == ["PostToolUse", "PreToolUse", "UserPromptSubmit"]


def test_changing_display_does_not_install_anything_by_itself():
    ctl("display", "restored")
    assert not user_settings().exists()


def test_project_install_and_status_lists_where_the_hooks_are():
    assert ctl("install", "--project")[0] == 0
    _, text = ctl("status")
    assert "project" in text and ".claude" in text and "hooks: installed" in text
    assert ctl("uninstall", "--project")[0] == 0
    assert "hooks: not installed" in ctl("status")[1]


def test_old_install_with_display_hook_is_silenced_by_the_default_setting(tmp_path):
    st = tmp_path / "st"
    guard.install(user_settings(), python="/py", restored_display=True)  # what 0.2.0 wrote
    post(st, f"Anh {NAME}")
    shown = guard.handle(ev("MessageDisplay", delta="<PERSON_1>\n", index=0, final=False), state_dir=st)
    assert shown is None


def test_purge_command_clears_stored_sessions(tmp_path):
    st = tmp_path / "st"
    post(st, f"Anh {NAME}")
    code, _ = ctl("purge", env={"VIPII_GUARD_DIR": str(st)})
    assert code == 0 and not list(st.glob("*.json"))


# ------------------------------------------------------------------ through the real CLI

def run(*args, stdin=b""):
    return subprocess.run([sys.executable, "-m", "vipii", "guard", *args], cwd=ROOT,
                          input=stdin, capture_output=True, env=dict(os.environ))


def test_cli_status_and_set():
    p = run("status")
    assert p.returncode == 0 and b"display: masked" in p.stdout
    assert run("display", "restored").returncode == 0
    assert b"display: restored" in run("ctl", "status").stdout


def test_cli_bad_input_exits_2():
    p = run("display", "loud")
    assert p.returncode == 2 and b"Traceback" not in p.stderr + p.stdout


def test_cli_without_words_is_still_the_hook_protocol():
    event = ev("PostToolUse", tool_name="Bash", tool_input={}, tool_response={"stdout": f"{NAME}"})
    p = run(stdin=json.dumps(event, ensure_ascii=False).encode("utf-8"))
    assert p.returncode == 0 and b"updatedToolOutput" in p.stdout
