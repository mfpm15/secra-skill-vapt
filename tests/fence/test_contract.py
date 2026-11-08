"""Offline contract tests; these do not prove kernel enforcement."""
import ipaddress
import json
import runpy
from pathlib import Path
from uuid import uuid4

import pytest

from app.gateway.fence import (FenceUnverified, SystemdFence, read_attestation,
                               scope_allowlist, validate_dns_answers)
from app.scope_guard import ScopePolicy


def sample_scope():
    return ScopePolicy.from_engagement("192.0.2.10", "192.0.2.0/24", (80, 443))


def load_helper():
    return runpy.run_path(str(Path(__file__).resolve().parents[2] / "deploy" / "secra-run"))


def test_exact_ip_fenced_even_when_scope_is_broad():
    assert scope_allowlist(sample_scope()) == ("192.0.2.10/32",)
    assert "192.0.2.0/24" not in scope_allowlist(sample_scope())
    assert "::/0" not in scope_allowlist(sample_scope())


def test_no_liveness_from_non_lab_configuration(tmp_path):
    path = tmp_path / "fabricated.json"
    path.write_text(json.dumps({"schema": 1, "result": "pass", "passed_tests": []}))
    with pytest.raises(FenceUnverified):
        read_attestation(path)
    with pytest.raises(FenceUnverified):
        SystemdFence(wrapper="/tmp/untrusted", attestation=str(path)).require_ready(sample_scope())


def test_cname_rebinding_and_mapped_ipv6_denied_offline():
    s = sample_scope()
    assert validate_dns_answers("192.0.2.10", (), ("192.0.2.10",), s) == ("192.0.2.10",)
    cases = [
        ("example.test", (), ("192.0.2.10",)),
        ("192.0.2.10", ("cdn.outside.test",), ("192.0.2.10",)),
        ("192.0.2.10", (), ("198.51.100.99",)),
        ("192.0.2.10", (), ("::ffff:192.0.2.10",)),
        ("192.0.2.10", (), ("2001:db8::1",)),
    ]
    for host, chain, ips in cases:
        with pytest.raises(FenceUnverified):
            validate_dns_answers(host, chain, ips, s)


def test_root_wrapper_is_not_arbitrary_runner():
    helper = load_helper()
    denied = helper["Denied"]
    with pytest.raises(denied):
        helper["command"](["exec", "--engagement", str(uuid4()), "--run",
                           str(uuid4()), "--", "/bin/sh", "-c", "id"])
    with pytest.raises(denied):
        helper["command"](["stop", "--run", "--all"])
    with pytest.raises(denied):
        helper["command"](["--systemd-override", "anything"])


def test_unit_argv_full_deny_both_families_and_no_dns_exception(monkeypatch):
    helper = load_helper()
    monkeypatch.setitem(helper["systemd_argv"].__globals__, "check_directory", lambda p: None)
    monkeypatch.setitem(helper["systemd_argv"].__globals__, "WORK", Path("/var/lib/secra/work"))
    monkeypatch.setitem(helper["systemd_argv"].__globals__, "EVIDENCE", Path("/var/lib/secra/evidence"))
    monkeypatch.setattr(Path, "is_dir", lambda p: True)
    monkeypatch.setattr(Path, "is_symlink", lambda p: False)
    class Stat:
        st_uid = 0
    monkeypatch.setattr(Path, "stat", lambda p: Stat())
    eid, rid = str(uuid4()), str(uuid4())
    binary = ["/usr/bin/nmap", *helper["NMAP_FIXED"], "192.0.2.10"]
    args = helper["systemd_argv"](eid, rid, binary, {"target": "192.0.2.10"})
    assert "--scope" in args and "--uid=secra" in args
    assert "--property=IPAddressDeny=any" in args
    assert "--property=IPAddressAllow=192.0.2.10/32" in args
    assert len([x for x in args if x.startswith("--property=IPAddressAllow=")]) == 1
    assert not any(":53" in x or "0.0.0.0/0" in x or "::/0" in x for x in args)
    assert "--property=MemoryMax=536870912" in args
    assert "--property=CPUQuota=50%" in args
    assert "--property=TasksMax=32" in args
    assert "--property=NoNewPrivileges=yes" in args
    assert "--property=PrivateTmp=yes" in args
    assert "--property=ProtectSystem=strict" in args
    assert args[-len(binary):] == binary


def test_root_wrapper_argv_enforced_even_if_tool_requests_other_scope(tmp_path, monkeypatch):
    h = load_helper()
    denied = h["Denied"]
    valid = {"target": "192.0.2.10", "binaries": {"nmap": "a"*64, "curl": "b"*64}}
    monkeypatch.setitem(h["verify_argv"].__globals__, "NMAP", "/usr/bin/nmap")
    for argv in [
        ["/bin/bash", "192.0.2.10"],
        ["/usr/bin/nmap", "-sV", "192.0.2.10"],
        ["/usr/bin/nmap", *h["NMAP_FIXED"], "198.51.100.1"],
        ["/usr/bin/curl", *h["CURL_FIXED"], "https://198.51.100.1:443/"],
        ["/usr/bin/curl", *h["CURL_FIXED"], "https://192.0.2.10:443/redirect"],
        ["/usr/bin/curl", *h["CURL_FIXED"], "https://192.0.2.10:443/?x=1"],
    ]:
        with pytest.raises(denied):
            h["verify_argv"](argv, valid)
