"""Offline regression tests for operator-owned lead registry and evidence gates."""
from __future__ import annotations

import json
from uuid import UUID, uuid4

import pytest

from app.evidence_vault import EvidenceVault
from app.loop.continuity import build_handoff, short_handoff
from app.loop.leads import LeadRegistry, LeadError
from app.loop.store import TaskStore
from app.mcp.dispatcher import ToolDispatcher


def scenario(tmp_path, mode="local"):
    store = TaskStore(tmp_path)
    tid = store.create("127.0.0.1", "127.0.0.1/32", mode=mode, authorized=True)
    return store, tid, LeadRegistry(store)


def sealed_receipt(store, tid, tool="local.http_head", status="completed"):
    rid = uuid4()
    vault = EvidenceVault(store.root / "evidence")
    writer = vault.begin(UUID(tid), rid)
    writer.append("stdout", b"synthetic offline test observation")
    writer.finish()
    ref = "evidence://" + tid + "/" + str(rid)
    audit = store.begin_tool_run(tid, tool)
    store.finish_tool_run(tid, audit, status, 0, 1, ref)
    return ref


def test_leads_are_private_append_only_and_visible_in_handoff(tmp_path):
    store, tid, reg = scenario(tmp_path)
    first = reg.create(tid, "web", "Check missing security header")
    assert first["status"] == "open" and first["version"] == 1
    assert len(reg.events(tid, first["id"])) == 1
    snapshot = build_handoff(store, tid)
    assert snapshot["lead_registry"]["counts"]["open"] == 1
    assert snapshot["unverified_hypotheses"][0]["lead_id"] == first["id"]
    assert "Check missing security header" not in json.dumps(snapshot)
    assert snapshot["verified_facts"] == []
    assert snapshot["metrics"]["verified_findings"] is None
    assert "127.0.0.1" not in json.dumps(snapshot)


def test_transition_and_negative_registry_are_durable(tmp_path):
    store, tid, reg = scenario(tmp_path)
    lead = reg.create(tid, "api", "Object authorization check")
    active = reg.transition(
        tid, lead["id"], "testing", reason="started", expected_version=1)
    assert active["version"] == 2
    negative = reg.transition(
        tid, lead["id"], "negative", reason="no_effect", expected_version=2)
    assert negative["version"] == 3
    assert reg.summary(tid)["negative_count"] == 1
    assert len(reg.events(tid, lead["id"])) == 3
    assert reg.events(tid, lead["id"])[-1]["reason"] == "no_effect"
    assert build_handoff(store, tid)["lead_registry"]["negative_count"] == 1
    with pytest.raises(LeadError, match="ILLEGAL"):
        reg.transition(tid, lead["id"], "verified", reason="operator_signoff",
                       expected_version=3, operator=True)
    reopened = reg.transition(
        tid, lead["id"], "testing", reason="reopened", expected_version=3)
    assert reopened["status"] == "testing"


def test_version_conflict_prevents_stealing_model_context(tmp_path):
    _, tid, reg = scenario(tmp_path)
    lead = reg.create(tid, "web", "Template sink review")
    reg.transition(tid, lead["id"], "testing", reason="started", expected_version=1)
    with pytest.raises(LeadError, match="STALE"):
        reg.transition(tid, lead["id"], "negative", reason="no_effect",
                       expected_version=1)
    assert reg.get(tid, lead["id"])["version"] == 2
    assert len(reg.events(tid, lead["id"])) == 2


def test_operator_signoff_needs_two_distinct_real_sealed_receipts(tmp_path):
    store, tid, reg = scenario(tmp_path, mode="local")
    initial = sealed_receipt(store, tid)
    independent = sealed_receipt(store, tid)
    lead = reg.create(tid, "web", "Header control review", primary_ref=initial)
    reg.transition(tid, lead["id"], "testing", reason="started", expected_version=1)
    requested = reg.transition(
        tid, lead["id"], "review_requested", reason="evidence_captured",
        expected_version=2)
    assert requested["version"] == 3
    with pytest.raises(LeadError, match="OPERATOR"):
        reg.transition(tid, lead["id"], "verified", reason="operator_signoff",
                       expected_version=3, evidence_ref=independent)
    with pytest.raises(LeadError, match="SECOND_RECEIPT"):
        reg.transition(tid, lead["id"], "verified", reason="operator_signoff",
                       expected_version=3, evidence_ref=initial, operator=True)
    verified = reg.transition(
        tid, lead["id"], "verified", reason="operator_signoff",
        expected_version=3, evidence_ref=independent, operator=True)
    assert verified["review_ref"] == independent
    assert verified["version"] == 4
    assert reg.summary(tid)["operator_verified_count"] == 1
    assert len(reg.events(tid, lead["id"])) == 4
    assert build_handoff(store, tid)["lead_registry"]["operator_verified_count"] == 1


def test_incompatible_evidence_and_simulated_mode_denied(tmp_path):
    store, tid, reg = scenario(tmp_path, mode="demo")
    fake = sealed_receipt(store, tid, status="simulated")
    with pytest.raises(LeadError, match="COMPLETED"):
        reg.create(tid, "web", "Fake finding review", primary_ref=fake)
    ref = sealed_receipt(store, tid, status="completed")
    lead = reg.create(tid, "web", "Synthetic finding note", primary_ref=ref)
    reg.transition(tid, lead["id"], "testing", reason="started", expected_version=1)
    reg.transition(tid, lead["id"], "review_requested",
                   reason="evidence_captured", expected_version=2)
    second = sealed_receipt(store, tid, status="completed")
    with pytest.raises(LeadError, match="SIMULATED_TASK"):
        reg.transition(tid, lead["id"], "verified", reason="operator_signoff",
                       expected_version=3, evidence_ref=second, operator=True)


def test_invalid_missing_unsealed_and_nonobservational_evidence_rejected(tmp_path):
    store, tid, reg = scenario(tmp_path)
    other = store.create("127.0.0.1", "127.0.0.1/32", mode="local", authorized=True)
    foreign = sealed_receipt(store, other)
    with pytest.raises(LeadError, match="INVALID"):
        reg.create(tid, "web", "Cross engagement review", primary_ref=foreign)
    non_observation = sealed_receipt(store, tid, tool="inventory.read")
    with pytest.raises(LeadError, match="COMPLETED"):
        reg.create(tid, "web", "Inventory not a finding", primary_ref=non_observation)
    bogus = "evidence://" + tid + "/" + str(uuid4())
    audit = store.begin_tool_run(tid, "local.http_head")
    store.finish_tool_run(tid, audit, "completed", 0, 1, bogus)
    with pytest.raises(LeadError, match="SEAL"):
        reg.create(tid, "web", "Missing evidence seal", primary_ref=bogus)
    with pytest.raises(LeadError, match="TITLE"):
        reg.create(tid, "web", "192.0.2.44")
    with pytest.raises(LeadError, match="TITLE"):
        reg.create(tid, "web", "token=supersecretvalue")


def test_lead_read_cannot_cross_engagement_boundary(tmp_path):
    store, tid, reg = scenario(tmp_path)
    second = store.create("127.0.0.1", "127.0.0.1/32", mode="local", authorized=True)
    lead = reg.create(tid, "network", "Service version confirmation")
    with pytest.raises(LeadError, match="NOT_FOUND"):
        reg.get(second, lead["id"])


def test_compact_mcp_handoff_carries_active_lead_without_title_or_scope(tmp_path):
    store, tid, reg = scenario(tmp_path)
    lead = reg.create(tid, "api", "Object permission hypothesis")
    snapshot = build_handoff(store, tid)
    summary = short_handoff(snapshot)
    assert lead["id"] in summary
    assert "open" in summary
    assert len(summary) <= 490
    assert "Object permission hypothesis" not in summary
    assert "127.0.0.1" not in summary
    assert "No findings verified" in summary


def test_actual_mcp_handoff_receipt_contains_safe_unfinished_lead(tmp_path):
    store, tid, reg = scenario(tmp_path, mode="demo")
    lead = reg.create(tid, "web", "Authentication flow question")
    store.start(tid)
    dispatcher = ToolDispatcher(tmp_path, store=store)
    response = dispatcher.call("workflow.handoff", {"task_id": tid})
    assert response["status"] == "completed"
    assert lead["id"] in response["summary"]
    assert "Authentication flow question" not in response["summary"]
    assert "127.0.0.1" not in response["summary"]
    assert response["masked"] is True
    assert response["output_ref"].startswith("evidence://")


def test_model_can_propose_bounded_unverified_lead_through_mcp(tmp_path):
    store, tid, reg = scenario(tmp_path, mode="demo")
    store.start(tid)
    dispatcher = ToolDispatcher(tmp_path, store=store)
    response = dispatcher.call("workflow.lead_propose", {
        "task_id": tid, "category": "web", "title": "Missing response header check"
    })
    assert response["status"] == "completed"
    assert response["masked"] is True
    assert response["output_ref"] is None
    assert "Missing response header check" not in response["summary"]
    assert len(reg.list(tid)) == 1
    assert reg.list(tid)[0]["status"] == "open"
    assert reg.summary(tid)["operator_verified_count"] == 0
    snapshot = dispatcher.call("workflow.handoff", {"task_id": tid})
    assert snapshot["status"] == "completed"
    assert reg.list(tid)[0]["id"] in snapshot["summary"]


def test_model_proposal_active_lead_cap_and_sensitive_title_gate(tmp_path):
    store, tid, reg = scenario(tmp_path, mode="demo")
    store.start(tid)
    dispatcher = ToolDispatcher(tmp_path, store=store)
    for number in range(5):
        response = dispatcher.call("workflow.lead_propose", {
            "task_id": tid, "category": "api",
            "title": "Test contract issue " + str(number)
        })
        assert response["status"] == "completed"
    sixth = dispatcher.call("workflow.lead_propose", {
        "task_id": tid, "category": "api", "title": "Test contract issue 5"
    })
    assert sixth["status"] == "blocked"
    assert len(reg.list(tid)) == 5
    bad = dispatcher.call("workflow.lead_propose", {
        "task_id": tid, "category": "web", "title": "192.0.2.42 example"
    })
    assert bad["status"] == "blocked"
    assert "192.0.2.42" not in str(bad)
    negative = reg.transition(
        tid, reg.list(tid)[0]["id"], "negative",
        reason="no_effect", expected_version=1)
    assert negative["status"] == "negative"
    reopened_budget = dispatcher.call("workflow.lead_propose", {
        "task_id": tid, "category": "api", "title": "Additional route review"
    })
    assert reopened_budget["status"] == "completed"
    assert reg.summary(tid)["negative_count"] == 1
    assert reg.summary(tid)["total_in_window"] == 6


def test_mcp_exposes_no_agent_verification_tool(tmp_path):
    store, tid, reg = scenario(tmp_path, mode="demo")
    dispatcher = ToolDispatcher(tmp_path, store=store)
    names = set(dispatcher.manifest.tools)
    assert "workflow.lead_propose" in names
    assert "workflow.lead_verify" not in names
    assert "workflow.lead_signoff" not in names
    assert dispatcher.manifest.get("workflow.lead_propose").risk == "R0"


def test_repeat_proposal_rejected_after_negative_record(tmp_path):
    store, tid, reg = scenario(tmp_path, mode="demo")
    store.start(tid)
    dispatcher = ToolDispatcher(tmp_path, store=store)
    args = {"task_id": tid, "category": "web", "title": "Header forwarding hypothesis"}
    assert dispatcher.call("workflow.lead_propose", args)["status"] == "completed"
    assert dispatcher.call("workflow.lead_propose", args)["status"] == "blocked"
    row = reg.list(tid)[0]
    reg.transition(tid, row["id"], "negative",
                   reason="no_effect", expected_version=1)
    assert dispatcher.call("workflow.lead_propose", args)["status"] == "blocked"
    assert len(reg.list(tid)) == 1
