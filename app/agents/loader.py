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
                   "privesc", "network", "reporting"})
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
                       step: int = 0) -> tuple[tuple[str, ...], str]:
    """Return the shortest relevant public knowledge snippets, at most two.

    No scan output, target, OS inventory or local secrets are inputs here.
    """
    if not isinstance(step, int) or step < 0:
        raise ProfileError("SKILL_STEP_INVALID")
    focus = {
        "demo.nmap_scan": "recon", "nmap.tcp_top20": "recon",
        "demo.httpx_probe": "web", "curl.http_head": "web",
        "report.summary": "reporting", "inventory.read": "recon",
    }.get(selected_tool, profile.skills[0])
    selected = [focus] if focus in profile.skills else [profile.skills[0]]
    if selected_tool is None and step == 0:
        selected = [profile.skills[0]]
    chunks = []
    for name in selected[:2]:
        if name not in NAMES:
            raise ProfileError("SKILL_NOT_REVIEWED")
        path = SKILLS / name / "SKILL.md"
        if path.is_symlink() or path.stat().st_size > 8192:
            raise ProfileError("SKILL_UNSAFE")
        content = path.read_text(encoding="utf-8")
        chunks.append(content[:1600])
    return tuple(selected), "\n\n".join(chunks)
