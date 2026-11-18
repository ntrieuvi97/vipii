import json
import os
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(*args, stdin=""):
    return subprocess.run(
        [sys.executable, "-m", "vipii", *args],
        input=stdin, capture_output=True, text=True, cwd=ROOT, check=True,
    ).stdout


def test_cli_analyze_outputs_json_entities():
    out = run("analyze", stdin="SĐT 0912345678")
    data = json.loads(out)
    assert [(e["type"], e["text"]) for e in data] == [("PHONE_NUMBER", "0912345678")]


def test_cli_anonymize_then_deanonymize_round_trip(tmp_path):
    mapfile = tmp_path / "map.json"
    text = "Khách hàng Nguyễn Văn An, SĐT 0912345678"
    anon = run("anonymize", "--map", str(mapfile), stdin=text)
    assert "Nguyễn Văn An" not in anon and "<PERSON_1>" in anon
    if sys.platform != "win32":  # POSIX modes only
        assert stat.S_IMODE(os.stat(mapfile).st_mode) == 0o600
    restored = run("deanonymize", "--map", str(mapfile), stdin=anon)
    assert restored == text


def test_cli_operator_and_custom_terms(tmp_path):
    terms = tmp_path / "secrets.txt"
    terms.write_text("Phượng Hoàng\n# comment\n\nFalcon\n", encoding="utf-8")
    out = run(
        "anonymize", "--map", str(tmp_path / "m.json"),
        "--op", "PHONE_NUMBER=mask", "--terms", f"PROJECT={terms}",
        stdin="Dự án Falcon, gọi 0912345678",
    )
    assert out == "Dự án <PROJECT_1>, gọi ******5678"
