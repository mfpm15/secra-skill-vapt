"""Real operator-captured HTTP evidence: strict host filtering and vault privacy."""
from __future__ import annotations

import json
from uuid import UUID

import pytest

from app.evidence_vault import EvidenceVault
from app.har_import import HARError, analyze_har, import_har
from app.loop.leads import LeadRegistry
from app.loop.store import TaskStore


def captured_har():
    return json.dumps({
        "log": {"version": "1.2", "entries": [
            {
                "request": {"url": "https://allowed.example.test/session",
                            "headers": [{"name": "Authorization",
                                         "value": "Bearer SECRET_PRIVATE_TOKEN"}]},
                "response": {"status": 200, "headers": [
                    {"name": "Content-Security-Policy", "value": "default-src 'self'"},
                    {"name": "Set-Cookie", "value": "sid=SECRET_COOKIE; HttpOnly; Secure; SameSite=Lax"}
                ], "content": {"text": "PRIVATE_BODY_EXAMPLE"}},
            },
            {
                "request": {"url": "https://out-of-scope.example.test/private",
                            "headers": [{"name": "Cookie", "value": "thirdparty=OUT_OF_SCOPE_SECRET"}]},
                "response": {"status": 200, "headers": [], "content": {"text": "THIRD_PARTY_PRIVATE"}}
            }
        ]}
    }).encode()


def setup(tmp_path):
    store = TaskStore(tmp_path)
    tid = store.create("127.0.0.1", "127.0.0.1/32",
                       mode="local", authorized=True)
    return store, tid


def test_filtered_real_har_is_sealed_without_leaking_credentials(tmp_path):
    store, tid = setup(tmp_path)
    summary = import_har(
        store, tid, captured_har(),
        approved_hosts=("allowed.example.test",),
        operator_scope_confirmed=True)
    assert summary["status"] == "completed"
    assert summary["accepted_entries"] == 1
    assert summary["out_of_host_allowlist_skipped"] == 1
    assert summary["vulnerabilities_verified"] == 0
    assert summary["no_network_requests_generated"] is True
    assert summary["header_presence_counts"]["csp_present"] == 1
    assert summary["cookie_attribute_counts"]["missing_httponly"] == 0
    assert "SECRET_PRIVATE_TOKEN" not in json.dumps(summary)
    assert "OUT_OF_SCOPE_SECRET" not in json.dumps(summary)
    assert "allowed.example.test" not in json.dumps(summary)
    run = store.tool_runs(tid)[0]
    assert run["tool"] == "operator.har_import"
    assert run["status"] == "completed"
    reference = summary["output_ref"]
    records = EvidenceVault(store.root / "evidence").verify_and_read(
        UUID(tid), UUID(reference.rsplit("/", 1)[-1]))
    sealed = records["stdout"]
    assert b"SECRET_PRIVATE_TOKEN" in sealed
    assert b"THIRD_PARTY_PRIVATE" not in sealed
    assert b"OUT_OF_SCOPE_SECRET" not in sealed
    assert b"out-of-scope.example.test" not in sealed
    # Observation can support operator review, but is not a verified finding.
    lead = LeadRegistry(store).create(
        tid, "web", "Review captured security headers", primary_ref=reference)
    assert lead["status"] == "open"


def test_operator_must_provide_exact_host_and_scope_affirmation(tmp_path):
    store, tid = setup(tmp_path)
    with pytest.raises(HARError, match="CONFIRMATION"):
        import_har(store, tid, captured_har(),
                   approved_hosts=("allowed.example.test",),
                   operator_scope_confirmed=False)
    with pytest.raises(HARError, match="HOST_INVALID"):
        analyze_har(captured_har(), allowed_hosts=("*.example.test",))
    with pytest.raises(HARError, match="NO_APPROVED_HOST"):
        analyze_har(captured_har(), allowed_hosts=("other.example.test",))
    assert store.tool_runs(tid) == []


def test_har_is_information_only_even_when_headers_absent():
    data = json.dumps({"log": {"entries": [{
        "request": {"url": "http://app.test/", "headers": []},
        "response": {"status": 404, "headers": []}
    }]}}).encode()
    filtered, observations = analyze_har(data, allowed_hosts=("app.test",))
    assert observations["status_categories"]["4xx"] == 1
    assert observations["header_presence_counts"]["hsts_present"] == 0
    assert observations["vulnerabilities_verified"] == 0
    assert "app.test" not in json.dumps(observations)
    assert b"app.test" in filtered
