"""Local, deterministic privacy and scope controls. No LLM participates in enforcement."""
import ipaddress
import json
import re
from urllib.parse import urlparse

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?\b")
BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}")
SECRET = re.compile(r"(?i)\b(password|passwd|api[_-]?key|authorization|secret|access[_-]?token|private[_-]?key)\s*[:=]\s*[^\s,;]+")
DOMAIN = re.compile(r"(?<![\w@])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![\w])")
ALLOWED_SERVICES = frozenset({"http", "https", "ssh", "smtp", "domain", "mysql", "postgresql", "ms-wbt-server", "microsoft-ds", "netbios-ssn", "ftp", "telnet", "unknown"})
MAX_SCOPE_NETS = 32

def redact(value: str) -> str:
    """Best-effort UI/log masking; NOT a guarantee for arbitrary sensitive text."""
    value = str(value)[:4000]
    value = SECRET.sub(r"\1=[REDACTED]", value)
    value = BEARER.sub("Bearer [REDACTED]", value)
    value = JWT.sub("[JWT_REDACTED]", value)
    value = EMAIL.sub("[EMAIL_REDACTED]", value)
    value = IPV4.sub("[IP_REDACTED]", value)
    value = DOMAIN.sub("[DOMAIN_REDACTED]", value)
    return value

def validate_scope(target: str, scope: str) -> tuple[str, list[str]]:
    try:
        ip = ipaddress.ip_address(target.strip())
    except ValueError as exc:
        raise ValueError("MVP hanya menerima satu alamat IP (bukan hostname/CIDR).") from exc
    if ip.version != 4 or not ip.is_global and not ip.is_private:
        raise ValueError("Alamat IP khusus/loopback/link-local tidak boleh menjadi target.")
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        raise ValueError("Alamat IP target dilarang oleh kebijakan keselamatan.")
    entries = [x.strip() for x in re.split(r"[,\n]+", scope) if x.strip()]
    if not entries or len(entries) > MAX_SCOPE_NETS:
        raise ValueError("Scope harus berisi 1 hingga 32 IP atau CIDR.")
    networks = []
    for entry in entries:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise ValueError("Scope mengandung alamat IP/CIDR tidak valid.") from exc
        if net.version != 4:
            raise ValueError("Scope IPv6 belum tersedia.")
        networks.append(net)
    if not any(ip in net for net in networks):
        raise ValueError("Target tidak berada dalam scope engagement.")
    return str(ip), [str(n) for n in networks]

def safe_model(model: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._:/+-]{1,110}", model or ""):
        raise ValueError("ID model tidak valid.")
    return model

def safe_gateway(base_url: str) -> str:
    parsed = urlparse(base_url)
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Gateway tidak valid.")
    local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (local and parsed.scheme == "http"):
        raise ValueError("Gateway remote harus HTTPS; HTTP hanya untuk loopback.")
    if not parsed.path.rstrip("/").endswith("/v1"):
        raise ValueError("Gateway harus berakhiran /v1.")
    return base_url.rstrip("/")

def llm_safe_payload(ports: list[dict]) -> dict:
    """Positive allowlist: never pass raw logs, target IP, hostnames, headers, or secrets."""
    services = []
    for item in ports[:30]:
        try:
            port = int(item.get("port", 0))
        except (ValueError, TypeError):
            continue
        service = str(item.get("service", "unknown")).lower()
        if service not in ALLOWED_SERVICES:
            service = "unknown"
        if 1 <= port <= 65535:
            services.append({"port": port, "protocol": "tcp", "service": service})
    return {"asset": "ASSET_001", "observed_open_services": services,
            "notice": "Do not infer a vulnerability from an open port."}

def assert_no_sensitive_payload(payload: dict) -> None:
    """Defense in depth: fail closed on forbidden keys and unexpected structures."""
    if set(payload) != {"asset", "observed_open_services", "notice"}:
        raise ValueError("Unexpected LLM payload keys")
    if payload["asset"] != "ASSET_001":
        raise ValueError("Unexpected asset alias")
    for svc in payload["observed_open_services"]:
        if set(svc) != {"port", "protocol", "service"} or svc["protocol"] != "tcp":
            raise ValueError("Unexpected service fields")
        if svc["service"] not in ALLOWED_SERVICES or not isinstance(svc["port"], int):
            raise ValueError("Unexpected service values")
    raw = json.dumps(payload)
    if IPV4.search(raw) or EMAIL.search(raw) or BEARER.search(raw) or JWT.search(raw):
        raise ValueError("Sensitive payload blocked")
