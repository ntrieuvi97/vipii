import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def run(*args, stdin=b"", env=None):
    return subprocess.run(
        [sys.executable, "-m", "vipii", *args], input=stdin, capture_output=True,
        cwd=ROOT, env=env, check=True,
    )


def test_cli_is_utf8_regardless_of_locale(tmp_path):
    env = dict(os.environ, LC_ALL="C", LANG="C", PYTHONIOENCODING="ascii", PYTHONUTF8="0")
    out = run("anonymize", "--map", str(tmp_path / "m.json"),
              stdin="Khách hàng Nguyễn Văn An".encode(), env=env).stdout
    assert out.decode("utf-8") == "Khách hàng <PERSON_1>"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks and modes")
def test_cli_map_write_ignores_planted_tmp_symlink(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    mapfile = tmp_path / "map.json"
    os.symlink(victim, str(mapfile) + ".tmp")
    run("anonymize", "--map", str(mapfile), stdin="SĐT 0912345678".encode())
    assert victim.read_text() == "keep me"
    assert stat.S_IMODE(os.stat(mapfile).st_mode) == 0o600


def test_cli_warns_when_hashing_without_salt(tmp_path):
    env = {k: v for k, v in os.environ.items() if k != "VIPII_SALT"}
    p = run("anonymize", "--map", str(tmp_path / "m.json"), "--op", "PHONE_NUMBER=hash",
            stdin="SĐT 0912345678".encode(), env=env)
    assert b"salt" in p.stderr.lower()
