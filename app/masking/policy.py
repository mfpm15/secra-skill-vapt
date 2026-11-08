"""Local privacy release rules. 'Trusted' is a policy tier, never trust in a provider."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ProviderTier = Literal["local", "trusted", "foreign"]


@dataclass(frozen=True)
class MaskPolicy:
    tier: ProviderTier = "foreign"
    mask_private_ip: bool = True
    mask_public_ip: bool = True
    mask_internal_hostname: bool = True
    mask_public_hostname: bool = True
    mask_email: bool = True
    mask_credentials: bool = True
    mask_cookie: bool = True
    mask_hash: bool = True
    mask_home_path: bool = True
    mask_customer: bool = True
    arbitrary_free_text_to_llm: bool = False


POLICIES: dict[str, MaskPolicy] = {
    "foreign": MaskPolicy(),
    "trusted": MaskPolicy(tier="trusted", mask_public_ip=False,
                          mask_public_hostname=False),
    "local": MaskPolicy(tier="local", mask_public_ip=False,
                        mask_public_hostname=False),
}


def get_policy(tier: ProviderTier = "foreign") -> MaskPolicy:
    """Unknown tier never silently weakens policy."""
    if tier not in POLICIES:
        raise ValueError("Unknown provider tier: egress denied")
    return POLICIES[tier]
