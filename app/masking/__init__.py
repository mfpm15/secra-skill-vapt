"""Single Phase-1 public masking gate. No LLM-driven redaction.

For outbound LLM context, for_llm=True requires the fixed, strictly
allowlisted structured service schema. Raw tool output is NEVER allowed to
take that path even when ordinary regex redaction appears successful.
"""
from __future__ import annotations

import json
from typing import Iterable

from .policy import MaskPolicy, get_policy, ProviderTier
from .redact import redact, StreamingRedactor, MaskingError, PlaceholderCollisionError
from .rehydrate import rehydrate, UnresolvedPlaceholderError, UnsafeRehydrationError
from .vault import MemoryVault, Vault, VaultError, KeyMissingError, PLACEHOLDER


class EgressDeniedError(RuntimeError):
    pass


def guard_mask(
    text: str,
    *,
    vault: MemoryVault | Vault | None = None,
    tier: ProviderTier = "foreign",
    customer_names: Iterable[str] = (),
    for_llm: bool = False,
) -> tuple[str, dict]:
    """Redact locally; remote LLM path is limited to a fixed typed schema."""
    if for_llm:
        try:
            from app.security import assert_no_sensitive_payload
            obj = json.loads(text)
            assert_no_sensitive_payload(obj)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise EgressDeniedError("Unstructured or unsafe model egress blocked") from exc
    masked, delta = redact(text, vault=vault, tier=tier, customer_names=customer_names)
    if for_llm and masked != text:
        raise EgressDeniedError("Structured payload required masking; request blocked")
    return masked, delta


def guard_unmask(
    text: str,
    vault: MemoryVault | Vault,
    *,
    expected_kind: str = "HOST",
    allowed_targets: Iterable[str] = (),
) -> str:
    """Resolve only a single typed, approved target; never a raw shell command."""
    if not PLACEHOLDER.fullmatch(text):
        raise UnsafeRehydrationError("Only a standalone typed placeholder is allowed")
    try:
        kind, value = vault.get_record(text)
    except KeyError as exc:
        raise UnresolvedPlaceholderError([text]) from exc
    if kind != expected_kind or kind not in {"HOST", "IP"}:
        raise UnsafeRehydrationError("Credential or mismatched type cannot be resolved as target")
    allowed = frozenset(allowed_targets)
    if not allowed or value not in allowed:
        raise UnsafeRehydrationError("Target is not explicitly authorized")
    resolved, missing = rehydrate(text, vault)
    if missing:
        raise UnresolvedPlaceholderError(missing)
    return resolved


__all__ = [
    "Vault", "MemoryVault", "VaultError", "KeyMissingError",
    "redact", "rehydrate", "guard_mask", "guard_unmask", "get_policy",
    "MaskPolicy", "StreamingRedactor", "MaskingError", "PlaceholderCollisionError",
    "UnresolvedPlaceholderError", "UnsafeRehydrationError", "EgressDeniedError",
]
