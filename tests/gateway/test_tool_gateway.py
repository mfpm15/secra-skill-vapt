import os
import sys
import threading
import time
from dataclasses import replace
from uuid import uuid4

import pytest

from app.tool_gateway import (ToolGateway, ToolCancelled, ToolTimedOut,
                              NetworkFenceUnavailable, OutputLimitExceeded,
                              build_fixed_argv, GatewayError)
from app.scope_guard import ScopePolicy, ScopeDenied
from app.tool_registry import (REGISTRY, StructuredToolIntent, ToolPolicy, ToolDenied)


def make_intent(action="nmap.tcp_top20", params=None):
    return StructuredToolIntent(uuid4(), uuid4(), "recon", action,
                                "192.0.2.10", {} if params is None else params)


def test_gateway_network_default_denied_before_subprocess(tmp_path, monkeypatch):
    gateway = ToolGateway(tmp_path)
    def forbidden(*args, **kwargs):
        raise AssertionError("Popen called without a network fence")
    monkeypatch.setattr("app.tool_gateway.subprocess.Popen", forbidden)
    intent = make_intent()
    with pytest.raises(NetworkFenceUnavailable):
        gateway.execute(intent, "192.0.2.10", "192.0.2.0/24", threading.Event())
    codes = [x["outcome"] for x in gateway.audit.events(intent.engagement_id)]
    assert codes == ["REQUESTED", "VALIDATED", "FENCE_BLOCKED"]
    with pytest.raises(GatewayError, match="DUPLICATE_REQUEST"):
        gateway.execute(intent, "192.0.2.10", "192.0.2.0/24", threading.Event())


def test_unapproved_scope_and_r3_fail_before_any_network(tmp_path):
    gateway = ToolGateway(tmp_path)
    bad = make_intent()
    with pytest.raises(ScopeDenied):
        gateway.execute(bad, "192.0.2.10", "198.51.100.0/24", threading.Event())
    r3 = make_intent("http.authenticated_test")
    with pytest.raises(ToolDenied):
        gateway.execute(r3, "192.0.2.10", "192.0.2.0/24", threading.Event())
    assert gateway.audit.events(r3.engagement_id)[-1]["outcome"] == "POLICY_BLOCKED"


def test_reviewed_argv_has_no_proxy_shell_redirect_or_dynamic_flags(monkeypatch):
    monkeypatch.setattr("app.tool_gateway._verified_binary", lambda tool: "/bin/" + tool)
    scope = ScopePolicy.from_engagement("192.0.2.10", "192.0.2.0/24", (443,))
    intent = make_intent("curl.http_head", {"port": 443})
    argv = build_fixed_argv(intent, "192.0.2.10", scope)
    assert argv[0] == "/bin/curl" and argv[1] == "-q"
    assert argv[-1] == "https://192.0.2.10:443/"
    assert "--noproxy" in argv and "*" in argv and "--max-redirs" in argv
    assert "--location" not in argv and "--proxy" not in argv
    with pytest.raises(ScopeDenied):
        build_fixed_argv(intent, "192.0.2.11", scope)


def test_real_offline_subprocess_sealed_before_local_read(tmp_path, monkeypatch):
    gateway = ToolGateway(tmp_path)
    intent = make_intent()
    # Internal test of process/evidence primitive; NOT an agent-callable adapter.
    argv = (sys.executable, "-u", "-c",
            "import sys;sys.stdout.buffer.write(b'private token');"
            "sys.stderr.buffer.write(b'private diagnostic')")
    receipt = gateway._run_fixed_process(argv, intent, REGISTRY[intent.action_id],
                                         uuid4(), threading.Event())
    assert receipt.exit_code == 0
    events = [x["outcome"] for x in gateway.audit.events(intent.engagement_id)]
    assert events == ["EXECUTION_STARTED", "SEALED", "COMPLETED"]
    data = gateway.vault.verify_and_read(intent.engagement_id, receipt.run_id)
    assert data == {"stdout": b"private token", "stderr": b"private diagnostic"}
    assert "private token" not in str(gateway.audit.events(intent.engagement_id))


def test_real_offline_process_cancelled_and_unsealed_data_blocked(tmp_path):
    gateway = ToolGateway(tmp_path)
    intent = make_intent()
    cancel = threading.Event()
    captured = []
    def job():
        try:
            gateway._run_fixed_process(
                (sys.executable, "-u", "-c",
                 "import sys,time;print('started',flush=True);time.sleep(30)"),
                intent, REGISTRY[intent.action_id], uuid4(), cancel)
        except BaseException as exc:
            captured.append(exc)
    thread = threading.Thread(target=job)
    thread.start()
    for _ in range(150):
        with gateway._lock:
            if gateway._active:
                break
        time.sleep(0.02)
    assert gateway._active
    cancel.set()
    thread.join(timeout=5)
    assert not thread.is_alive() and len(captured) == 1
    assert isinstance(captured[0], ToolCancelled)
    assert not gateway._active
    assert gateway.audit.events(intent.engagement_id)[-1]["outcome"] == "CANCELLED"


def test_real_offline_process_timeout_and_output_limits(tmp_path):
    gateway = ToolGateway(tmp_path)
    timeout_intent = make_intent()
    spec = replace(REGISTRY["nmap.tcp_top20"], timeout_seconds=1)
    with pytest.raises(ToolTimedOut):
        gateway._run_fixed_process(
            (sys.executable, "-u", "-c", "import time;time.sleep(30)"),
            timeout_intent, spec, uuid4(), threading.Event())
    limit_intent = make_intent()
    small = replace(REGISTRY["nmap.tcp_top20"], max_stdout_bytes=64)
    with pytest.raises(OutputLimitExceeded):
        gateway._run_fixed_process(
            (sys.executable, "-u", "-c", "print('S'*10000)"),
            limit_intent, small, uuid4(), threading.Event())
    assert gateway.audit.events(timeout_intent.engagement_id)[-1]["outcome"] == "TIMEOUT"
    assert gateway.audit.events(limit_intent.engagement_id)[-1]["outcome"] == "OUTPUT_LIMIT"
