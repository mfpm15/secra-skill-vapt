"""Phase 2: deny-by-default target/port checks. OS fencing is a separate boundary."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlsplit

from .masking import guard_unmask, PLACEHOLDER
from .security import validate_scope


class ScopeDenied(ValueError):
    """No target, port, address family, or network route may be implicitly approved."""


@dataclass(frozen=True)
class ScopePolicy:
    target: str
    networks: tuple[ipaddress.IPv4Network, ...]
    ports: frozenset[int]
    version: int = 1

    @classmethod
    def from_engagement(cls, target: str, scope: str, ports: Iterable[int],
                        *, version: int = 1) -> "ScopePolicy":
        try:
            canonical, networks = validate_scope(target, scope)
            permitted = frozenset(ports)
            if (not permitted or any(type(p) is not int or not 1 <= p <= 65535
                                      for p in permitted) or version < 1):
                raise ValueError("Invalid port allowlist or scope version")
            return cls(canonical, tuple(ipaddress.IPv4Network(n) for n in networks),
                       permitted, version)
        except (TypeError, ValueError) as exc:
            raise ScopeDenied("SCOPE_INVALID") from exc


def authorized_target(target_ref: str, scope: ScopePolicy, *, vault=None) -> str:
    if not isinstance(target_ref, str):
        raise ScopeDenied("TARGET_INVALID")
    if target_ref.startswith("<") or PLACEHOLDER.fullmatch(target_ref):
        if vault is None:
            raise ScopeDenied("PLACEHOLDER_UNRESOLVED")
        try:
            target_ref = guard_unmask(target_ref, vault, expected_kind="IP",
                                      allowed_targets=[scope.target])
        except Exception as exc:
            raise ScopeDenied("PLACEHOLDER_UNRESOLVED") from exc
    try:
        address = ipaddress.ip_address(target_ref)
    except ValueError as exc:
        # DNS names and unreviewed URLs are not supported in the IPv4-only MVP.
        raise ScopeDenied("HOSTNAME_NOT_SUPPORTED") from exc
    if address.version != 4 or str(address) != scope.target:
        raise ScopeDenied("TARGET_OUT_OF_SCOPE")
    return str(address)


def enforce_scope_per_connection(target: str, peer_ip: str, port: int,
                                 scope: ScopePolicy) -> None:
    if type(port) is not int or port not in scope.ports:
        raise ScopeDenied("PORT_OUT_OF_SCOPE")
    authorized_target(target, scope)
    try:
        peer = ipaddress.ip_address(peer_ip)
    except ValueError as exc:
        raise ScopeDenied("PEER_INVALID") from exc
    if (peer.version != 4 or str(peer) != scope.target
            or not any(peer in net for net in scope.networks)
            or peer.is_loopback or peer.is_link_local or peer.is_multicast
            or peer.is_unspecified or peer.is_reserved):
        raise ScopeDenied("PEER_OUT_OF_SCOPE")


def fixed_http_url(target: str, port: int, scope: ScopePolicy) -> str:
    enforce_scope_per_connection(target, target, port, scope)
    if port not in {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 3000, 5000, 9443}:
        raise ScopeDenied("NOT_AN_HTTP_PORT")
    scheme = "https" if port in {443, 8443, 9443} else "http"
    return scheme + "://" + target + ":" + str(port) + "/"


def reject_untrusted_url(url: str, scope: ScopePolicy) -> None:
    """Extra defensive helper. Tool intents do not accept a URL parameter at all."""
    try:
        parts = urlsplit(url)
        if (parts.scheme not in {"http", "https"} or parts.username or parts.password
                or parts.query or parts.fragment or parts.path != "/"
                or not parts.hostname or parts.port is None):
            raise ScopeDenied("URL_NOT_CANONICAL")
        if fixed_http_url(parts.hostname, parts.port, scope) != url:
            raise ScopeDenied("URL_NOT_CANONICAL")
    except (ValueError, TypeError) as exc:
        raise ScopeDenied("URL_NOT_CANONICAL") from exc
