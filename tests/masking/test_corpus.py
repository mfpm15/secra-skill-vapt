"""Golden expected files were authored and committed BEFORE masker implementation."""
from pathlib import Path

import pytest

from app.masking import MemoryVault, redact, rehydrate

ROOT = Path(__file__).resolve().parents[1] / "corpus"
RAW = ROOT / "raw"
EXPECTED = ROOT / "expected"
NAMES = sorted(p.name for p in RAW.iterdir() if p.is_file())


@pytest.mark.parametrize("name", NAMES)
def test_synthetic_golden_fixture_exact_output(name: str):
    assert len(NAMES) == 9
    assert "[SINTETIS]" in (ROOT / "SOURCES.md").read_text(encoding="utf-8")
    source = (RAW / name).read_text(encoding="utf-8")
    expected = (EXPECTED / name).read_text(encoding="utf-8")
    vault = MemoryVault()
    customers = ["Helios Analytics"] if name == "client-record.txt" else ()
    got, delta = redact(source, vault=vault, tier="foreign", customer_names=customers)
    assert got == expected
    restored, missing = rehydrate(got, vault)
    assert missing == []
    assert restored == source
    assert delta["count"] > 0


def test_all_golden_files_are_hand_authored_pairs():
    assert {p.name for p in RAW.iterdir() if p.is_file()} == {
        p.name for p in EXPECTED.iterdir() if p.is_file()
    }
    assert len(NAMES) == 9
