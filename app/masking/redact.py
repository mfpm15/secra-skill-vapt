"""Deterministic, span-based masking. No LLM participates in detection.

Mapping stays in local vault. vault_delta exposes placeholder/kind metadata
only, never raw values. Unstructured tool text is local inspection data;
remote LLM egress still requires a separate strict schema allowlist.
"""
from __future__ import annotations
import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable

from .policy import MaskPolicy, get_policy, ProviderTier
from .vault import MemoryVault, Vault

RESERVED = re.compile(r"<(?:HOST|IP|EMAIL|TOKEN|COOKIE|HASH|PATH|CUSTOMER)_[1-9]\d*>")
EMAIL = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")
IPV4 = re.compile(r"(?<![A-Za-z0-9_.:-])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9_.:-])")
IPV6 = re.compile(r"(?<![A-Za-z0-9_.:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.%]*")
HOST = re.compile(r"(?<![A-Za-z0-9_.@-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_.-])")
HOME_PATH = re.compile(r"(?<!\w)(?:/home/[A-Za-z0-9_.-]+|/Users/[A-Za-z0-9_.-]+|C:\\Users\\[A-Za-z0-9_.-]+)(?:[/\\][^\s<>'\";,)]+)*")
AUTH = re.compile(
    r"(?im)(?:Authorization|Proxy-Authorization)\s*:\s*"
    r"(?:Bearer|Bea[ \t\r\n]+rer|Basic|Bas[ \t\r\n]+ic)\s+"
    r"([A-Za-z0-9._~+/\-=]+(?:\r?\n[ \t]+[A-Za-z0-9._~+/\-=]+)*)"
)
SET_COOKIE = re.compile(r"(?im)^Set-Cookie:\s*[A-Za-z0-9_-]+\s*=\s*([^;\r\n]+)")
COOKIE_LINE = re.compile(r"(?im)^Cookie:\s*([^\r\n]+)")
COOKIE_VALUE = re.compile(r"(?:^|;\s*)[A-Za-z0-9_-]+\s*=\s*([^;\r\n]+)")
NAMED_SECRET = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])(?:password|passwd|api[_-]?key|access[_-]?token|"
    r"auth[_-]?token|private[_-]?key|secret|token|session)\s*[:=]\s*"
    r"([^&#\s;\"'<>]+)"
)
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b")
HASH_NAMED = re.compile(r"(?i)\b(?:sha256|sha1|md5|hash)\s*[:=]\s*([a-f0-9]{32,128})\b")
HASH_HEX = re.compile(r"(?<![A-Za-z0-9])(?:[a-fA-F0-9]{128}|[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})(?![A-Za-z0-9])")
HASH_BCRYPT = re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")
HASH_ARGON2 = re.compile(r"\$argon2(?:id|i|d)\$[^\s<>\"']+")
INTERNAL_SUFFIX = (".internal", ".local", ".lan", ".corp", ".intra")
CUSTOMER_FIELD = re.compile(r"(?im)^(?:Customer|Client|Tenant|Organization|Company):[ \t]*([^\r\n<>]+?)[ \t]*$")


class MaskingError(RuntimeError):
    pass


class PlaceholderCollisionError(MaskingError):
    pass


class UnsupportedInputError(MaskingError):
    pass


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    kind: str
    priority: int


def _spans(text: str, pattern: re.Pattern, kind: str, priority: int, group: int = 0) -> list[Span]:
    return [Span(m.start(group), m.end(group), kind, priority)
            for m in pattern.finditer(text) if m.start(group) != m.end(group)]


def _policy_ip(value: str, policy: MaskPolicy) -> bool:
    try:
        addr = ipaddress.ip_address(value.split("%", 1)[0])
        return policy.mask_public_ip if addr.is_global else policy.mask_private_ip
    except ValueError:
        return False


def _policy_host(value: str, policy: MaskPolicy) -> bool:
    internal = value.lower().rstrip(".").endswith(INTERNAL_SUFFIX)
    return policy.mask_internal_hostname if internal else policy.mask_public_hostname


def detect_spans(text: str, policy: MaskPolicy, customer_names: Iterable[str] = ()) -> list[Span]:
    """Resolve overlapping sensitive spans without changing the input."""
    spans = []
    if policy.mask_credentials:
        spans += _spans(text, AUTH, "TOKEN", 120, group=1)
        spans += _spans(text, NAMED_SECRET, "TOKEN", 110, group=1)
        spans += _spans(text, JWT, "TOKEN", 105)
    if policy.mask_cookie:
        spans += _spans(text, SET_COOKIE, "COOKIE", 115, group=1)
        for m in COOKIE_LINE.finditer(text):
            for p in COOKIE_VALUE.finditer(m.group(1)):
                spans.append(Span(m.start(1)+p.start(1), m.start(1)+p.end(1), "COOKIE", 115))
    if policy.mask_hash:
        spans += _spans(text, HASH_NAMED, "HASH", 100, group=1)
        spans += _spans(text, HASH_BCRYPT, "HASH", 100)
        spans += _spans(text, HASH_ARGON2, "HASH", 100)
        spans += _spans(text, HASH_HEX, "HASH", 95)
    if policy.mask_home_path:
        spans += _spans(text, HOME_PATH, "PATH", 90)
    if policy.mask_customer:
        spans += _spans(text, CUSTOMER_FIELD, "CUSTOMER", 89, group=1)
        for name in sorted(set(customer_names), key=lambda x: (-len(x), x.casefold())):
            if not isinstance(name, str) or not (2 <= len(name) <= 150):
                raise UnsupportedInputError("Invalid customer registry entry")
            p = re.compile(r"(?<!\w)" + re.escape(name) + r"(?!\w)", re.IGNORECASE)
            spans += _spans(text, p, "CUSTOMER", 88)
    if policy.mask_email:
        spans += _spans(text, EMAIL, "EMAIL", 80)
    for p in (IPV4, IPV6):
        for m in p.finditer(text):
            if _policy_ip(m.group(), policy):
                spans.append(Span(m.start(), m.end(), "IP", 75))
    for m in HOST.finditer(text):
        if _policy_host(m.group(), policy):
            spans.append(Span(m.start(), m.end(), "HOST", 60))
    kept: list[Span] = []
    for span in sorted(spans, key=lambda x: (-x.priority, -(x.end-x.start), x.start)):
        if not any(span.start < old.end and old.start < span.end for old in kept):
            kept.append(span)
    return sorted(kept, key=lambda x: x.start)


def redact(
    text: str,
    *,
    vault: MemoryVault | Vault | None = None,
    tier: ProviderTier = "foreign",
    customer_names: Iterable[str] = (),
) -> tuple[str, dict]:
    """Return masked text and placeholder-only delta; no unmasked value in delta.

    Without vault, mapping is ephemeral and cannot be rehydrated later.
    """
    if not isinstance(text, str) or len(text.encode("utf-8")) > 2_000_000:
        raise UnsupportedInputError("Only UTF-8 text up to 2MB is supported")
    if RESERVED.search(text):
        raise PlaceholderCollisionError("Reserved placeholder appeared in untrusted input")
    if vault is None:
        vault = MemoryVault()
    selected = detect_spans(text, get_policy(tier), customer_names)
    output = []
    last = 0
    added = []
    existing = set(getattr(vault, "_values", {}).keys())
    for span in selected:
        output.append(text[last:span.start])
        placeholder = vault.put(span.kind, text[span.start:span.end])
        output.append(placeholder)
        if placeholder not in existing:
            added.append({"placeholder": placeholder, "kind": span.kind})
            existing.add(placeholder)
        last = span.end
    output.append(text[last:])
    return "".join(output), {"added": added, "count": len(added), "tier": tier}


class StreamingRedactor:
    """No chunk leaves the masker until finalization; 2MB hard memory cap."""

    def __init__(self, *, vault: MemoryVault | Vault | None = None,
                 tier: ProviderTier = "foreign", customer_names: Iterable[str] = ()) -> None:
        self.vault = vault or MemoryVault()
        self.tier = tier
        self.customers = tuple(customer_names)
        self._parts: list[str] = []
        self._size = 0
        self._closed = False

    def feed(self, chunk: str) -> str:
        if self._closed or not isinstance(chunk, str):
            raise UnsupportedInputError("Invalid stream state/chunk")
        self._size += len(chunk.encode("utf-8"))
        if self._size > 2_000_000:
            self._parts.clear()
            self._closed = True
            raise UnsupportedInputError("Stream too large: quarantined")
        self._parts.append(chunk)
        return ""

    def finish(self) -> tuple[str, dict]:
        if self._closed:
            raise UnsupportedInputError("Stream already finalized")
        self._closed = True
        text = "".join(self._parts)
        self._parts.clear()
        return redact(text, vault=self.vault, tier=self.tier, customer_names=self.customers)
