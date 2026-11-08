"""Read-only progressive skill loader, never arbitrary repository paths."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from app.mcp.manifest import RISKS

ROOT = Path(__file__).resolve().parents[2]
PROFILES = Path(__file__).with_name("profiles")
SKILLS = ROOT / "skills"
NAMES = frozenset({"recon", "web", "api", "ad", "ad_enum",
                   "privesc", "network", "reporting", "tls"})
SPECIALISTS = frozenset({"recon", "web", "api", "network",
                         "verification", "reporting"})


class ProfileError(ValueError):
    pass


@dataclass(frozen=True)
class AgentProfile:
    name: str
    max_risk: str
    tools: frozenset[str]
    skills: tuple[str, ...]
    system_prompt: str

    def allows(self, tool: str, risk: str) -> bool:
        return tool in self.tools and RISKS[risk] <= RISKS[self.max_risk]


def load_profile(name: str = "recon") -> AgentProfile:
    if name not in SPECIALISTS:
        raise ProfileError("AGENT_PROFILE_UNKNOWN")
    file = PROFILES / (name + ".json")
    if file.is_symlink() or file.stat().st_size > 8192:
        raise ProfileError("AGENT_PROFILE_UNSAFE")
    info = json.loads(file.read_text(encoding="utf-8"))
    if (set(info) != {"name", "max_risk", "skills", "tools", "system_prompt"}
            or info["name"] != name or info["max_risk"] not in RISKS
            or not isinstance(info["skills"], list)
            or not 1 <= len(info["skills"]) <= 4
            or not set(info["skills"]).issubset(NAMES)
            or not isinstance(info["tools"], list)
            or not all(isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", x)
                       for x in info["tools"])
            or not isinstance(info["system_prompt"], str)
            or not 1 <= len(info["system_prompt"]) <= 600):
        raise ProfileError("AGENT_PROFILE_SCHEMA_INVALID")
    return AgentProfile(name, info["max_risk"], frozenset(info["tools"]),
                        tuple(info["skills"]), info["system_prompt"])


def progressive_skills(profile: AgentProfile, *, selected_tool: str | None = None,
                       step: int = 0,
                       services: list[dict] | None = None) -> tuple[tuple[str, ...], str]:
    """Serve only one relevant 1800-char SKILL.md slice per step.

    The selector reads already-sanitized service types and the last reviewed
    tool name. It never reads the real target, raw logs, credentials or URLs.
    """
    if not isinstance(step, int) or step < 0:
        raise ProfileError("SKILL_STEP_INVALID")
    catalog_prefix = (selected_tool or "").split(".", 1)[0]
    category = {
        "recon": "recon", "web": "web", "api": "api",
        "tls": "tls", "auth": "ad", "data": "privesc",
        "other": "network",
    }.get(catalog_prefix)
    if selected_tool and not category:
        category = {
            "demo.nmap_scan": "recon", "nmap.tcp_top20": "recon",
            "demo.httpx_probe": "web", "curl.http_head": "web",
            "local.http_head": "web", "report.summary": "reporting",
            "inventory.read": "recon",
        }.get(selected_tool)
    observed_services = set()
    for item in (services or [])[:30]:
        if isinstance(item, dict):
            observed_services.add(str(item.get("service", "unknown")).lower())
    if not category and step > 0:
        if observed_services.intersection({"https", "http"}):
            category = "web"
        elif observed_services.intersection({"ssh"}):
            category = "tls"
    if not category:
        category = profile.skills[0]
    if category not in profile.skills:
        category = profile.skills[0]
    if category not in NAMES:
        raise ProfileError("SKILL_NOT_REVIEWED")
    path = SKILLS / category / "SKILL.md"
    if path.is_symlink() or path.stat().st_size > 24000:
        raise ProfileError("SKILL_UNSAFE")
    contents = path.read_text(encoding="utf-8")
    if not contents.startswith("---\n") or len(contents) > 24000:
        raise ProfileError("SKILL_SCHEMA_INVALID")
    # Progressive step 0: trigger/sequence, step 1: combination and
    # interpretation, step 2+: pitfalls and safe stopping rules.
    blocks = contents.split("\n## ")
    if len(blocks) < 8:
        raise ProfileError("SKILL_SECTIONS_MISSING")
    if step == 0:
        chosen = blocks[:3]
    elif step == 1:
        chosen = [blocks[0], *blocks[3:5]]
    else:
        chosen = [blocks[0], *blocks[5:8]]
    body = ("\n## ".join(chosen))[:1800]
    return (category,), body
