from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def test_cli_check_prints_masked_and_unresolved_list():
    sample = ROOT / "tests" / "corpus" / "raw" / "httpx.jsonl"
    result = subprocess.run([sys.executable, "-m", "app.masking", "check", str(sample)],
        cwd=ROOT, text=True, capture_output=True, timeout=12)
    assert result.returncode == 0, result.stderr
    assert "<HOST_1>" in result.stdout
    assert "<TOKEN_1>" in result.stdout
    assert "portal.corp.internal" not in result.stdout
    assert "verySecret123456" not in result.stdout
    assert "unresolved: []" in result.stdout


def test_cli_fails_on_untrusted_reserved_placeholder(tmp_path):
    source = tmp_path / "attack.txt"
    source.write_text("attacker provides <HOST_9>")
    result = subprocess.run([sys.executable, "-m", "app.masking", "check", str(source)],
        cwd=ROOT, text=True, capture_output=True, timeout=12)
    assert result.returncode == 2
    assert "MASKING_CHECK_FAILED" in result.stderr
    assert "attacker provides" not in result.stdout
