"""Explicit operator-mode label; never bypasses the kernel egress fence.

'dev' permits only already-reviewed offline/loopback self-test behavior.
It is not a grant to run Kali network tools without OS isolation. Live Kali
operations remain fail-closed until independent kernel attestation.
"""
from __future__ import annotations

import os


class FenceModeError(ValueError):
    pass


def get_fence_mode() -> str:
    mode = os.environ.get("SECRA_FENCE_MODE", "strict").strip().lower()
    if mode not in {"strict", "dev"}:
        raise FenceModeError("FENCE_MODE_INVALID")
    return mode


def fence_label(mode: str, *, local: bool = False,
                attested: bool = False) -> str:
    if mode not in {"strict", "dev"}:
        raise FenceModeError("FENCE_MODE_INVALID")
    if attested:
        return "kernel_verified"
    if local:
        return "unfenced" if mode == "dev" else "local_loopback_only"
    return "blocked_until_kernel_verified"
