"""Operator-controlled HAR import: real observed HTTP data, zero target traffic.

The user supplies an allowlist of EXACT program-approved hostnames. The
importer rejects all unrelated entries before sealing the filtered HAR inside
the existing AES-GCM vault. No raw URLs, credentials, cookie values or bodies
are ever returned to a model or the CLI summary.

A captured request is a real observation, not a verified vulnerability.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from app.evidence_vault import EvidenceVault
from app.loop.store import TaskStore

MAX_FILE_SIZE = 2 * 1024 * 1024
MAX_ENTRIES = 150
MAX_HOSTS = 20
HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
STATUSES = frozenset({"completed"})

class HARError(ValueError):
    pass


def _hostname(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 253:
        raise HARError("HAR_HOST_INVALID")
    name = value.lower().strip().rstrip(".")
    if ("*" in name or "_" in name or ".." in name or not HOST_RE.fullmatch(name)
            or any(label.startswith("-") or label.endswith("-")
                   for label in name.split("."))):
        raise HARError("HAR_HOST_INVALID")
    # No DNS lookup: exact host literal only. Public suffix/asset ownership
    # cannot be proven by a hostname string.
    return name


def _headers(raw: object) -> dict[str, list[str]]:
    output: dict[str, list[str]] = {}
    if not isinstance(raw, list) or len(raw) > 150:
        raise HARError("HAR_HEADERS_INVALID")
    for item in raw:
        if not isinstance(item, dict):
            raise HARError("HAR_HEADERS_INVALID")
        name, value = item.get("name"), item.get("value")
        if not isinstance(name, str) or not isinstance(value, str):
            raise HARError("HAR_HEADERS_INVALID")
        output.setdefault(name.lower(), []).append(value)
    return output


def analyze_har(file: bytes, *, allowed_hosts: tuple[str, ...]) -> tuple[bytes, dict]:
    if not isinstance(file, bytes) or not 20 <= len(file) <= MAX_FILE_SIZE:
        raise HARError("HAR_FILE_SIZE_INVALID")
    if not isinstance(allowed_hosts, tuple) or not 1 <= len(allowed_hosts) <= MAX_HOSTS:
        raise HARError("HAR_APPROVED_HOSTS_REQUIRED")
    approved = {_hostname(host) for host in allowed_hosts}
    try:
        doc = json.loads(file)
        entries = doc["log"]["entries"]
    except (ValueError, TypeError, KeyError) as exc:
        raise HARError("HAR_INVALID_JSON") from exc
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise HARError("HAR_ENTRIES_LIMIT")
    accepted = []
    skipped = 0
    https_entries = 0
    counts = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
    header_observations = {"hsts_present": 0, "csp_present": 0,
                           "x_content_type_options_present": 0}
    cookie_counts = {"set_cookie": 0, "missing_httponly": 0,
                     "missing_secure_on_https": 0, "missing_samesite": 0}

    for entry in entries:
        if not isinstance(entry, dict):
            raise HARError("HAR_ENTRY_INVALID")
        req, res = entry.get("request"), entry.get("response")
        if not isinstance(req, dict) or not isinstance(res, dict):
            raise HARError("HAR_ENTRY_INVALID")
        url = req.get("url")
        if not isinstance(url, str) or len(url) > 2048:
            raise HARError("HAR_URL_INVALID")
        try:
            parsed = urlsplit(url)
            hostname = _hostname(parsed.hostname)
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                raise HARError("HAR_PORT_INVALID")
        except (ValueError, AttributeError, TypeError) as exc:
            raise HARError("HAR_URL_INVALID") from exc
        if (parsed.scheme not in {"http", "https"} or parsed.username is not None
                or parsed.password is not None or hostname not in approved):
            skipped += 1
            continue
        if not isinstance(res.get("status"), int) or not 100 <= res["status"] <= 599:
            raise HARError("HAR_STATUS_INVALID")
        headers = _headers(res.get("headers", []))
        _headers(req.get("headers", []))
        accepted.append(entry)  # raw capture stays encrypted and local
        category = str(res["status"])[0] + "xx"
        counts[category if category in counts else "other"] += 1
        if parsed.scheme == "https":
            https_entries += 1
        if "strict-transport-security" in headers and parsed.scheme == "https":
            header_observations["hsts_present"] += 1
        if "content-security-policy" in headers:
            header_observations["csp_present"] += 1
        if "x-content-type-options" in headers:
            header_observations["x_content_type_options_present"] += 1
        for cookie in headers.get("set-cookie", []):
            cookie_counts["set_cookie"] += 1
            low = cookie.lower()
            if "httponly" not in low:
                cookie_counts["missing_httponly"] += 1
            if parsed.scheme == "https" and "secure" not in low:
                cookie_counts["missing_secure_on_https"] += 1
            if "samesite" not in low:
                cookie_counts["missing_samesite"] += 1

    if not accepted:
        raise HARError("HAR_NO_APPROVED_HOST_ENTRIES")
    # Persist *only* selected entries. Other hosts, URLs, headers and cookies
    # are never sealed in this engagement's imported evidence.
    filtered = {
        "log": {"version": "1.2", "creator": {"name": "SECRA-local-filter", "version": "1"},
                "entries": accepted}
    }
    encoded = json.dumps(filtered, separators=(",", ":"), ensure_ascii=False).encode()
    if len(encoded) > MAX_FILE_SIZE:
        raise HARError("HAR_FILTERED_TOO_LARGE")
    return encoded, {
        "schema": "secra-har-observations-v1",
        "asset": "ASSET_001",
        "approved_host_count": len(approved),
        "accepted_entries": len(accepted),
        "out_of_host_allowlist_skipped": skipped,
        "https_entries": https_entries,
        "status_categories": counts,
        "header_presence_counts": header_observations,
        "cookie_attribute_counts": cookie_counts,
        "vulnerabilities_verified": 0,
        "no_network_requests_generated": True,
        "note": ("Informational observations only; missing headers or cookie "
                 "attributes are not automatically bounty-eligible findings."),
    }


def import_har(store: TaskStore, task_id: str, file: bytes,
               *, approved_hosts: tuple[str, ...],
               operator_scope_confirmed: bool) -> dict:
    task = store.require(task_id)
    if operator_scope_confirmed is not True:
        raise HARError("HAR_OPERATOR_SCOPE_CONFIRMATION_REQUIRED")
    sanitized_har, summary = analyze_har(file, allowed_hosts=approved_hosts)
    started = time.monotonic()
    audit_id = store.begin_tool_run(task["id"], "operator.har_import")
    eid, rid = uuid.UUID(task["id"]), uuid.uuid4()
    reference = None
    try:
        writer = EvidenceVault(store.root / "evidence").begin(eid, rid)
        try:
            for offset in range(0, len(sanitized_har), 65536):
                writer.append("stdout", sanitized_har[offset:offset + 65536])
            writer.finish()
        except BaseException:
            writer.abort()
            raise
        reference = "evidence://" + task["id"] + "/" + str(rid)
        store.finish_tool_run(
            task["id"], audit_id, "completed", 0,
            min(7_200_000, int((time.monotonic() - started) * 1000)), reference)
        store.append(task["id"], "tool", "operator.har_import", "done",
                     "Operator-filtered HAR evidence sealed locally.", reference)
    except BaseException:
        # An incomplete audit record is deliberately left visible for review;
        # the integrity checker will not call the case complete.
        raise
    return {"status": "completed", "output_ref": reference, "masked": True,
            **summary}
