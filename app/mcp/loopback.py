"""Single-purpose loopback-only HTTP HEAD, not a Kali tool or shell.

This action is a separate local self-test adapter, isolated from the live Kali
gateway. It cannot resolve hosts, redirect, use a proxy, read a response body,
send arbitrary headers or connect to a non-loopback address. The TCP source
address and verified peer are both required to be literal IPv4 loopback.
"""
from __future__ import annotations

import http.client
import json
import socket
from uuid import UUID, uuid4

from app.evidence_vault import EvidenceVault
from app.security import redact


class LocalProbeDenied(RuntimeError):
    pass


def run_head(*, target: str, scope: str, port: int, vault: EvidenceVault,
             engagement_id: UUID) -> tuple[int, str, str]:
    if (target != "127.0.0.1" or scope != "127.0.0.1/32"
            or type(port) is not int or not 1024 <= port <= 65535):
        raise LocalProbeDenied("LOCAL_TARGET_OR_PORT_NOT_APPROVED")
    conn = http.client.HTTPConnection(
        "127.0.0.1", port, timeout=3, source_address=("127.0.0.1", 0))
    try:
        conn.connect()
        peer = conn.sock.getpeername()
        local = conn.sock.getsockname()
        if peer[0] != "127.0.0.1" or local[0] != "127.0.0.1" or peer[1] != port:
            raise LocalProbeDenied("LOCAL_SOCKET_PEER_MISMATCH")
        conn.request("HEAD", "/", body=None,
                     headers={"Host": "127.0.0.1", "Connection": "close"})
        response = conn.getresponse()
        status = response.status
        if type(status) is not int or not 100 <= status <= 599:
            raise LocalProbeDenied("LOCAL_RESPONSE_INVALID")
        # No response headers or body leave this adapter.
        raw = json.dumps({"local_only": True, "target_alias": "ASSET_001",
                          "method": "HEAD", "status": status, "port": port,
                          "peer_verified": True},
                         separators=(",", ":"), sort_keys=True).encode()
        rid = uuid4()
        writer = vault.begin(engagement_id, rid)
        try:
            writer.append("stdout", raw)
            writer.finish()
        except BaseException:
            writer.abort()
            raise
        return status, "LOCAL HEAD: status " + str(status) + " on loopback port " + str(port) + ".", (
            "evidence://" + str(engagement_id) + "/" + str(rid))
    except (OSError, http.client.HTTPException) as exc:
        raise LocalProbeDenied("LOCAL_HTTP_HEAD_FAILED") from exc
    finally:
        conn.close()
