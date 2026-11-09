"""Executive + chronological security report: no fabricated verified finding."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from app.evidence_vault import EvidenceVault
from app.loop.store import TaskStore
from app.loop.leads import LeadRegistry
from app.workspace import WorkspaceManager
from app.professional_report import build_report, NarrativeError

ROOT = Path(__file__).resolve().parents[2]


def setup(tmp_path, mode="local"):
    store = TaskStore(tmp_path)
    tid = store.create(
        "127.0.0.1", "127.0.0.1/32", mode=mode, authorized=True)
    store.start(tid)
    return store, tid, LeadRegistry(store)


def reviewed_receipt(store, tid):
    uid = uuid4()
    writer = EvidenceVault(store.root / "evidence").begin(UUID(tid), uid)
    writer.append("stdout", b"controlled local observation, no private target")
    writer.finish()
    ref = "evidence://" + tid + "/" + str(uid)
    audit = store.begin_tool_run(tid, "local.http_head")
    store.finish_tool_run(tid, audit, "completed", 0, 7, ref)
    return ref


def operator(lead_id, refs, *, confirmed=True):
    return {
        "engagement_title": "VAPT Assessment - Authorized Test Application",
        "client_alias": "TEST_CLIENT",
        "objectives": ["Confirm authorization and session boundary behavior"],
        "scope_description": "a controlled local web fixture",
        "assessment_constraints": [
            "Operator-authorized identities only, no network scanning outside approved lab"
        ],
        "authorization_reference": "LAB-APPROVAL-2026-1",
        "reviewer_identity": "Local test operator",
        "operator_review_confirmed": confirmed,
        "findings": [{
            "lead_id": lead_id, "title": "Cross-role control was bypassed",
            "severity": "medium", "cwe": "CWE-639",
            "expected": "Role A cannot read records owned by role B.",
            "observed": "The controlled test role accessed a record owned by the second laboratory test identity.",
            "business_impact": "Data exposure would cross a verified fixture role boundary under the demonstrated controlled conditions.",
            "prerequisites": "Two test identities and an operator-authorized lab fixture.",
            "reproduction_steps": [
                "Log in using an operator-approved fixture identity.",
                "Submit the controlled fixture request and compare role-specific results."
            ],
            "countercheck": "The same request with an unrelated fixture role was denied under the same test setup.",
            "root_cause": "The fixture performed object lookup before checking the caller's ownership.",
            "remediation": "Enforce object ownership before every object-specific data lookup.",
            "retest": "Confirm denial for the foreign test role while the legitimate owner continues to work.",
            "reviewer_reproduced": True,
            "evidence_refs": refs,
        }]
    }


def verified_case(tmp_path):
    store, tid, registry = setup(tmp_path)
    first, second = reviewed_receipt(store, tid), reviewed_receipt(store, tid)
    lead = registry.create(tid, "api", "Controlled object ownership review",
                           primary_ref=first)
    registry.transition(tid, lead["id"], "testing",
                        reason="started", expected_version=1)
    registry.transition(tid, lead["id"], "review_requested",
                        reason="evidence_captured", expected_version=2)
    registry.transition(
        tid, lead["id"], "verified", reason="operator_signoff",
        expected_version=3, evidence_ref=second, operator=True
    )
    WorkspaceManager(tmp_path / "engagements").write_manifest(tid)
    return store, tid, lead, [first, second]


def test_professional_report_contains_exec_story_and_proven_review(tmp_path):
    store, tid, lead, refs = verified_case(tmp_path)
    report = build_report(store, tid, operator(lead["id"], refs))
    assert report["quality"] == "reviewed"
    assert report["confirmed_findings"] == 1
    md = report["markdown"]
    for expected in (
        "## 1. Executive summary",
        "## 3. Chronological evidence narrative",
        "### Event 1",
        "## 4. Findings summary",
        "## 5. Verified finding details",
        "## 6. Unverified and rejected hypotheses",
        "## 7. Limitations, cleanup and follow-up",
        "expected", "Observed behavior", "Retest acceptance",
        "Cross-role control was bypassed",
        "Local test operator",
        refs[0], refs[1],
    ):
        assert expected.lower() in md.lower(), expected
    assert "SIMULATED Nmap" not in md
    assert "127.0.0.1" not in md


def test_unreviewed_model_claim_cannot_be_promoted(tmp_path):
    store, tid, registry = setup(tmp_path)
    lead = registry.create(tid, "web", "Unreviewed candidate vulnerability")
    WorkspaceManager(tmp_path / "engagements").write_manifest(tid)
    payload = operator(lead["id"], [], confirmed=False)
    result = build_report(store, tid, payload)
    assert result["confirmed_findings"] == 0
    assert result["quality"] == "draft_requires_operator_review"
    assert result["excluded_candidates"][0]["issues"]
    assert "No confirmed findings" in result["markdown"]


def test_case_integrity_drift_blocks_promotion(tmp_path):
    store, tid, lead, refs = verified_case(tmp_path)
    case_file = tmp_path / "engagements" / tid / "01-recon" / "drift.txt"
    case_file.write_text("source changed after manifest")
    report = build_report(store, tid, operator(lead["id"], refs))
    assert report["confirmed_findings"] == 0
    assert report["quality"] == "draft_requires_operator_review"
    assert "case_integrity_not_verified" in report["excluded_candidates"][0]["issues"]


def test_report_cli_private_input_and_exclusive_output(tmp_path):
    store, tid, lead, refs = verified_case(tmp_path)
    script = ROOT / "scripts" / "secra_professional_report.py"
    source = tmp_path / "review.json"
    source.write_text(json.dumps(operator(lead["id"], refs)))
    os.chmod(source, 0o600)
    output = tmp_path / "professional.md"
    args = [
        sys.executable, str(script), "--data-dir", str(tmp_path),
        "--task-id", tid, "--input", str(source),
        "--output", str(output), "--strict",
    ]
    first = subprocess.run(args, cwd="/tmp", capture_output=True, text=True)
    assert first.returncode == 0, first.stderr
    assert output.stat().st_mode & 0o777 == 0o600
    assert "Executive summary" in output.read_text()
    second = subprocess.run(args, cwd="/tmp", capture_output=True, text=True)
    assert second.returncode == 1
