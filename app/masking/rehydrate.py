"""Local-only placeholder reversal. No arbitrary command execution is permitted."""
from __future__ import annotations

import re

from .vault import MemoryVault, Vault, PLACEHOLDER

# Recognize valid and spoofed placeholders; unknown values become a diagnostic
# marker, not a string an execution adapter may interpret as a hostname.
ANY_PLACEHOLDER = re.compile(r"<[A-Z][A-Z0-9_]{1,90}>")
PARTIAL = re.compile(r"<(?:HOST|IP|EMAIL|TOKEN|COOKIE|HASH|PATH|CUSTOMER)_[0-9]*(?![0-9>])")


class UnresolvedPlaceholderError(RuntimeError):
    def __init__(self, unresolved: list[str]):
        self.unresolved = unresolved
        super().__init__("UNRESOLVED_PLACEHOLDER: execution withheld")


class UnsafeRehydrationError(RuntimeError):
    pass


def rehydrate(text: str, vault: MemoryVault | Vault) -> tuple[str, list[str]]:
    """Replace known placeholders; unknown ones become UNRESOLVED_PLACEHOLDER.

    Call guard_unmask() rather than passing the resulting text to a tool.
    """
    if not isinstance(text, str) or len(text) > 2_000_000:
        raise UnsafeRehydrationError("Invalid rehydration input")
    unresolved = []
    def resolve(match: re.Match) -> str:
        marker = match.group(0)
        if not PLACEHOLDER.fullmatch(marker):
            unresolved.append(marker)
            return "UNRESOLVED_PLACEHOLDER"
        try:
            return vault.get(marker)
        except KeyError:
            unresolved.append(marker)
            return "UNRESOLVED_PLACEHOLDER"
    output = ANY_PLACEHOLDER.sub(resolve, text)
    if PARTIAL.search(output):
        unresolved.append("PARTIAL_PLACEHOLDER")
        output = "UNRESOLVED_PLACEHOLDER"
    return output, unresolved
