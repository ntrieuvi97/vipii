"""Keep every test away from the developer's real vipii/Claude configuration."""
import pytest

GUARD_ENV = ("VIPII_GUARD", "VIPII_GUARD_PROMPT", "VIPII_GUARD_DISPLAY", "VIPII_GUARD_RESTORE_EDITS",
             "VIPII_GUARD_TERMS", "VIPII_GUARD_DIR", "VIPII_GUARD_CONFIG", "CLAUDE_CONFIG_DIR")


@pytest.fixture(autouse=True)
def _isolated_guard_environment(tmp_path, monkeypatch):
    for name in GUARD_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("VIPII_GUARD_CONFIG", str(tmp_path / "cfg" / "guard-config.json"))
    monkeypatch.setenv("VIPII_GUARD_DIR", str(tmp_path / "guard-state"))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "claude"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))  # anything that forgets an override stays here
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)
