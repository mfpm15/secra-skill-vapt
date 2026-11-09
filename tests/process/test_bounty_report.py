"""Offline bug-bounty report gates; never claim tests or submission without proof."""
from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

import pytest

from app.bugbounty_report import ReportError, evaluate, render_draft, write_private
from app.evidence_vault import EvidenceVault
from app.loop.leads import LeadRegistry
from app.loop.store import TaskStore
from app.workspace import WorkspaceManager


def setup(tmp_path, mode="local"):
    store = TaskStore(tmp_path)
    tid = store.create("127.0.0.1", "127.0.0.1/32",
                       mode=mode, authorized=True)
    leads = LeadRegistry(store)
    lead = leads.create(tid, "web", "Synthetic security boundary hypothesis")
    WorkspaceManager(tmp_path / "engagements").write_manifest(tid)
    return store, tid, leads, lead


def draft():
    return {
        "program": "Example authorized lab program",
        "program_url": "https://example.test/program/rules",
        "policy_checked_at_utc": "2026-11-09T13:00:00+00:00",
        "asset": "ASSET_001 local authorized lab",
        "asset_scope_confirmed": True,
        "automation_allowed": False,
        "rules_acknowledged": True,
        "title": "Confirmed local security boundary finding",
        "weakness": "A documented authentication boundary fails in the local fixture.",
        "severity": "medium",
        "prerequisites": "Use two authorized laboratory accounts for this finding.",
        "steps": [
            "Step one uses a dedicated test account in the local fixture.",
            "Step two reproduces the boundary failure using test-only records.",
        ],
        "observed_result": "The controlled fixture returned a mismatched authorization result.",
        "security_impact": "The observation would cross the fixture account boundary under documented test conditions.",
        "root_cause": "Access-control enforcement occurs after the unsafe lookup.",
        "remediation": "Apply authorization before returning object-specific information.",
        "operator_reviewed": True,
        "program_disclosure_allowed": True,
        "poc_reproduced_by_operator": True,
        "rate_limit_complied": True,
    }


def seal(store, tid):
    rid = uuid4()
    writer = EvidenceVault(store.root / "evidence").begin(UUID(tid), rid)
    writer.append("stdout", b"controlled offline observation in lab")
    writer.finish()
    ref = "evidence://" + tid + "/" + str(rid)
    audit = store.begin_tool_run(tid, "local.http_head")
    store.finish_tool_run(tid, audit, "completed", 0, 1, ref)
    return ref


def verified_lead(store, tid, registry, lead):
    first, second = seal(store, tid), seal(store, tid)
    row = registry.transition(tid, lead["id"], "testing",
                              reason="started", expected_version=1,
                              evidence_ref=first)
    row = registry.transition(tid, lead["id"], "review_requested",
                              reason="evidence_captured", expected_version=2)
    return registry.transition(
        tid, lead["id"], "verified", reason="operator_signoff",
        expected_version=3, evidence_ref=second, operator=True)


def test_unreviewed_or_demo_findings_never_pass_gate(tmp_path):
    store, tid, registry, lead = setup(tmp_path, mode="demo")
    result = evaluate(store, tid, lead["id"], draft())
    assert result["ready_for_final_human_review"] is False
    assert "demo_mode_cannot_be_submitted" in result["issues"]
    assert result["platform_submission_performed"] is False
    assert "INCOMPLETE" in render_draft(draft(), result)


def test_verified_local_finding_still_needs_human_policy_and_poc_checks(tmp_path):
    store, tid, registry, lead = setup(tmp_path)
    verified_lead(store, tid, registry, lead)
    report = draft()
    result = evaluate(store, tid, lead["id"], report)
    assert result["ready_for_final_human_review"] is True
    assert result["platform_submission_performed"] is False
    assert len(result["evidence_refs"]) == 2
    not_ready = dict(report, poc_reproduced_by_operator=False,
                     rate_limit_complied=False)
    blocked = evaluate(store, tid, lead["id"], not_ready)
    assert not blocked["ready_for_final_human_review"]
    assert "poc_reproduced_by_operator_not_confirmed" in blocked["issues"]
    assert "rate_limit_complied_not_confirmed" in blocked["issues"]


def test_report_draft_is_private_and_cannot_overwrite(tmp_path):
    store, tid, registry, lead = setup(tmp_path)
    result = evaluate(store, tid, lead["id"], draft())
    path = tmp_path / "report.md"
    write_private(path, render_draft(draft(), result))
    assert path.is_file()
    assert path.stat().st_mode & 0o777 == 0o600
    assert "not submitted" in path.read_text().lower()
    with pytest.raises(ReportError, match="EXISTS"):
        write_private(path, "overwritten")
    assert "INCOMPLETE" in path.read_text()


def test_extra_sensitive_fields_are_rejected(tmp_path):
    store, tid, registry, lead = setup(tmp_path)
    payload = dict(draft(), auth_token="private-token")
    with pytest.raises(ReportError, match="UNKNOWN"):
        evaluate(store, tid, lead["id"], payload)
