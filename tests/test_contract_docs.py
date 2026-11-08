"""Guard documentation deliverables and pinned graph adapter boundaries.

These are snapshot/invariant checks; they DO NOT claim phases 1–8 are implemented.
"""
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DELIVERABLES = (
    "audit-existing.md",
    "masking.md",
    "router.md",
    "gateway.md",
    "runtime.md",
    "ui.md",
    "plan.md",
)
IMMUTABLE_BLOBS = {
    "vendor/sapper_v2/sapper.py": "5aa390332ed47becca1eb678365fc5cee71c79a1",
    "app/sapper_integration.py": "18f5cf4b7ca7921abaffc407f53d11f5834c1dab",
}


def _git_blob_hash(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def test_protected_graph_core_and_frontier_adapter_byte_identical():
    for relpath, expected in IMMUTABLE_BLOBS.items():
        assert _git_blob_hash(ROOT / relpath) == expected, relpath


def test_seven_requested_contract_artifacts_exist_and_are_versioned():
    for relpath in DELIVERABLES:
        path = ROOT / relpath
        assert path.is_file(), relpath
        text = path.read_text(encoding="utf-8")
        assert text.startswith("# "), relpath
        assert len(text) > 400, relpath
    assert "707c25f6747c641e33cfd3f2dd0422daf8bf7e76" in (
        ROOT / "audit-existing.md"
    ).read_text()


def test_all_new_contracts_have_signatures_and_phases_are_ordered():
    for relpath in DELIVERABLES[1:]:
        text = (ROOT / relpath).read_text(encoding="utf-8")
        assert "def " in text, relpath
    plan = (ROOT / "plan.md").read_text(encoding="utf-8")
    assert plan.count("## Phase ") == 8
    assert [plan.index(f"## Phase {n} ") for n in range(1, 9)] == sorted(
        plan.index(f"## Phase {n} ") for n in range(1, 9)
    )
    assert plan.index("## Phase 1 ") < plan.index("## Phase 2 ") < plan.index("## Phase 6 ")
    assert (ROOT / "docs/legacy-porting-plan-10-steps.md").is_file()
