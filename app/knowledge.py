"""Locally curated skill registry; only bundled, reviewed public methodology reaches LLMs."""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "knowledge"
SLUG = re.compile(r"^[a-z][a-z0-9-]{2,80}$")
SAFE = frozenset({"common","http","https","ssh","ftp","smtp","domain","mysql",
                  "postgresql","microsoft-ds","ms-wbt-server","unknown","cloud","mobile","code"})

@lru_cache(maxsize=1)
def catalog() -> list[dict]:
    raw = json.loads((ROOT / "catalog.json").read_text(encoding="utf-8"))
    if not isinstance(raw, list) or len(raw) > 100:
        raise ValueError("Invalid knowledge catalog")
    ids = set()
    for entry in raw:
        if not isinstance(entry, dict) or not SLUG.fullmatch(entry.get("id", "")):
            raise ValueError("Unsafe skill id")
        if entry["id"] in ids:
            raise ValueError("Duplicate skill")
        ids.add(entry["id"])
    return raw

def find_skill(skill_id: str) -> dict | None:
    if not SLUG.fullmatch(skill_id):
        return None
    return next((entry for entry in catalog() if entry["id"] == skill_id), None)

def content(skill_id: str) -> str:
    item = find_skill(skill_id)
    if item is None:
        raise KeyError("Unknown skill")
    # Path is derived only from the vetted bundled catalog, never raw user input.
    path = ROOT / "skills" / item["id"] / "SKILL.md"
    if not path.is_file():
        raise ValueError("Skill source missing")
    return path.read_text(encoding="utf-8")[:6500]

def select_skills(services: list[dict], limit: int = 6) -> list[dict]:
    """Deterministic routing; every assessment receives scope and quality review."""
    names = {"common"}
    for item in services[:50]:
        service = item.get("service", "")
        if isinstance(service, str) and service in SAFE:
            names.add(service)
    # Web and HTTPS testing is relevant only if those service classes were observed.
    matches = [s for s in catalog() if names.intersection(s["tags"])]
    rank = {
        "scope-and-engagement": 0,
        "network-service-discovery": 1,
        "http-security-configuration": 2,
        "tls-transport-review": 3,
        "api-contract-assessment": 4,
        "authentication-session-review": 5,
        "authorization-and-business-logic": 6,
        "finding-verification": 7,
        "reporting-and-retest": 8,
    }
    return sorted(matches, key=lambda s: rank.get(s["id"], 9))[:max(1, min(limit, 12))]

def safe_skill_context(services: list[dict]) -> tuple[list[str], str]:
    """Only local, static authored skill text; no raw target/evidence in prompt."""
    selected = select_skills(services, limit=5)
    ids = [s["id"] for s in selected]
    # Public, locally-curated reference content. No dynamic corpus, HTML or URLs fetched.
    excerpts = []
    for skill in selected:
        body = content(skill["id"])
        excerpts.append("## " + skill["title"] + "\n" + body[:1450])
    return ids, "\n\n".join(excerpts)[:8500]
