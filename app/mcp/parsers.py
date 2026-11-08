"""Bounded, evidence-safe normalizers for reviewed security-tool output formats.

Input is untrusted *local* bytes from a sealed evidence record, not from an
LLM. Only a small positive allowlist of structured observations can cross
the model boundary: ports/status/severity/algorithm families/counts. No IPs,
hostnames, cookies, URL query parameters, paths, request/response bodies,
tokens, usernames, password values, or raw tool text are forwarded.
"""
from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET

from app.security import ALLOWED_SERVICES
from .manifest import ToolManifest

MAX_RAW_BYTES = 1_000_000
MAX_ITEMS = 64
SEVERITIES = frozenset({"info", "low", "medium", "high", "critical", "unknown"})
PROTOCOLS = frozenset({"TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3", "SSLv2", "SSLv3"})
STATES = frozenset({"open", "closed", "filtered", "unfiltered", "unknown"})


class ParseError(ValueError):
    pass


def _status(value) -> int | None:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if 100 <= n <= 599 else None


def _port(value) -> int | None:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if 1 <= n <= 65535 else None


def _service(value) -> str:
    name = str(value).lower()
    return name if name in ALLOWED_SERVICES else "unknown"


def _severity(value) -> str:
    name = str(value).lower()
    return name if name in SEVERITIES else "unknown"


def _safe_token(value, default="unknown") -> str:
    token = str(value)
    if re.fullmatch(r"[A-Za-z0-9_.-]{1,72}", token):
        return token
    return default


def _nmap(xml_text: str) -> list[dict]:
    if re.search(r"(?i)<!\s*(?:DOCTYPE|ENTITY)", xml_text):
        raise ParseError("XML_DTD_NOT_ALLOWED")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ParseError("NMAP_XML_INVALID") from exc
    if root.tag != "nmaprun":
        raise ParseError("NMAP_XML_ROOT_INVALID")
    result = []
    for item in root.findall(".//port")[:MAX_ITEMS]:
        port = _port(item.get("portid"))
        if port is None:
            continue
        state = item.find("state")
        service = item.find("service")
        result.append({
            "asset": "ASSET_001", "port": port,
            "protocol": "udp" if item.get("protocol") == "udp" else "tcp",
            "state": state.get("state") if state is not None and
                state.get("state") in STATES else "unknown",
            "service": _service(service.get("name")) if service is not None else "unknown",
        })
    return result


def _json_lines(text: str):
    results = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if len(results) == MAX_ITEMS:
            break
        try:
            item = json.loads(line)
        except ValueError as exc:
            raise ParseError("JSONL_INVALID") from exc
        if not isinstance(item, dict):
            raise ParseError("JSONL_NONOBJECT")
        results.append(item)
    return results


def _objects(text: str):
    try:
        value = json.loads(text)
    except ValueError as exc:
        raise ParseError("JSON_INVALID") from exc
    if isinstance(value, list):
        return [item for item in value[:MAX_ITEMS] if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    raise ParseError("JSON_NONOBJECT")


def _httpx(text: str) -> list[dict]:
    records = []
    for item in _json_lines(text):
        code = _status(item.get("status_code", item.get("status-code")))
        port = _port(item.get("port"))
        if code is not None:
            records.append({"asset": "ASSET_001", "status": code,
                            "port": port, "service": "https" if
                            str(item.get("url", "")).startswith("https://") else "http"})
    return records


def _nuclei(text: str) -> list[dict]:
    records = []
    for item in _json_lines(text):
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        records.append({
            "asset": "ASSET_001",
            "template_id": _safe_token(item.get("template-id", item.get("templateID", ""))),
            "severity": _severity(info.get("severity")),
            "type": _safe_token(item.get("type", "unknown")),
            "verified": bool(item.get("verified", False)),
        })
    return records


def _tls(text: str) -> list[dict]:
    versions = sorted({t for t in PROTOCOLS if t in text})
    return [{"asset": "ASSET_001", "protocol": v} for v in versions]


def _endpoint(text: str) -> list[dict]:
    # Paths can contain PII, private namespaces and untrusted strings.
    # Count endpoint observations only; never forward their actual URLs.
    try:
        items = _json_lines(text)
    except ParseError:
        # Legacy endpoint tool formats are not guaranteed JSONL.
        return [{"asset": "ASSET_001", "endpoint_count": min(
            len([v for v in text.splitlines() if v.strip()]), MAX_ITEMS)}]
    return [{"asset": "ASSET_001", "endpoint_count": len(items)}]


def _http_status(text: str) -> list[dict]:
    match = re.search(r"(?m)^HTTP/\d(?:\.\d)?\s+([1-5]\d\d)\b", text)
    status = _status(match.group(1)) if match else None
    return [{"asset": "ASSET_001", "status": status}] if status else []


def _generic(raw: bytes) -> list[dict]:
    return [{"asset": "ASSET_001", "bytes": len(raw),
             "lines": min(99999, raw.count(b"\n") + int(bool(raw and not raw.endswith(b"\n"))))}]


def parse_tool_output(tool_name: str, raw: bytes, *,
                      manifest: ToolManifest | None = None) -> dict:
    """Return only allowlisted values; errors are metadata, never raw evidence."""
    if not isinstance(raw, bytes) or len(raw) > MAX_RAW_BYTES:
        raise ParseError("RAW_OUTPUT_INVALID_OR_TOO_LARGE")
    definition = (manifest or ToolManifest()).get(tool_name)
    fmt = (definition.metadata or {}).get("output_pattern", "generic")
    digest = hashlib.sha256(raw).hexdigest()
    if not raw:
        return {"tool": tool_name, "format": fmt, "count": 0, "entries": [],
                "raw_sha256": digest, "masked": True, "parse_status": "empty"}
    text = raw.decode("utf-8", errors="replace")
    try:
        if fmt == "nmap_xml":
            entries = _nmap(text)
        elif fmt == "httpx_jsonl":
            entries = _httpx(text)
        elif fmt == "nuclei_jsonl":
            entries = _nuclei(text)
        elif fmt in {"tls_text", "tls_json", "ssh_json"}:
            entries = _tls(text)
        elif fmt in {"endpoints_jsonl", "endpoints_text"}:
            entries = _endpoint(text)
        elif fmt == "http_headers":
            entries = _http_status(text)
        elif fmt in {"ffuf_json", "masscan_json", "wpscan_json", "findings_json",
                     "searchsploit_json", "simulated_json"}:
            # Structured JSON may contain credentials; expose counts only.
            entries = [{"asset": "ASSET_001", "records": len(_objects(text))}]
        elif fmt == "auth_summary":
            entries = [{"asset": "ASSET_001", "credential_values": "REDACTED",
                        "authentication_events": min(9999, text.count("\n") + 1)}]
        elif fmt in {"dns_jsonl", "findings_text", "dns_text", "domains_text",
                     "whois_text", "snmp_text", "http_text", "generic", "http_status",
                     "metadata_json"}:
            entries = _generic(raw)
        else:
            entries = _generic(raw)
        return {"tool": tool_name, "format": fmt, "count": len(entries),
                "entries": entries[:MAX_ITEMS], "raw_sha256": digest,
                "masked": True, "parse_status": "parsed" if fmt != "generic" else "metadata_only"}
    except (ParseError, ValueError, TypeError):
        # Never echo an unsafe token from a malformed log back to the model.
        return {"tool": tool_name, "format": fmt, "count": 0, "entries": [],
                "raw_sha256": digest, "masked": True, "parse_status": "rejected"}
