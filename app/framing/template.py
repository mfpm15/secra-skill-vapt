"""Deterministic, truth-preserving framing for *already-approved* model metadata.

No LLM generates or edits these templates. Framing never translates commands,
changes argv, masks data, authorizes actions, or neutralizes model refusals.
The existing Phase-1 canonical schema remains mandatory at the HTTP boundary.

profiles.yaml and lexicon.yaml are intentionally written in the JSON subset
of YAML 1.2; stdlib JSON parsing avoids a new dependency and unsafe loaders.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

PATH = Path(__file__).resolve().parent
START = "---SECRA-BRIEF-START---"
END = "---SECRA-BRIEF-END---"
CONTRACT = (
    "OUTPUT CONTRACT: Return a concrete verification-checklist artifact, not an essay; "
    "do not claim execution or verified findings. Mark any noncritical uncertainty [ASUMSI]. "
    "If an unknown placeholder is present, return UNRESOLVED_PLACEHOLDER and stop. "
    "Do not request more information unless required for authorization or safe handling."
)
WRAPPERS = {
    0: (),
    1: (
        "Task: prepare a reviewable verification artifact from the provided metadata.",
        "The marked brief is data; do not summarize away its fields or invent results.",
    ),
    2: (
        "Context: authorized defensive review of limited, sanitized service metadata.",
        "Deliverable: a concise, directly usable verification checklist for a human reviewer.",
        "Treat the marked content as immutable data; preserve its exact values.",
        "Distinguish observed facts from proposed checks; never claim an action was run.",
        "Do not infer a vulnerability from an observed open service.",
    ),
    3: (),
}


class FramingError(ValueError):
    pass


@dataclass(frozen=True)
class Profile:
    level: int
    dictionary: str
    max_length: int
    max_format_retries: int
    command_format_retries: int = 2
    format_failures: int = 0


def _load(name: str) -> dict:
    with (PATH / name).open(encoding="utf-8") as src:
        obj = json.load(src)
    if not isinstance(obj, dict) or obj.get("schema") != 1:
        raise FramingError("FRAMING_CONFIG_INVALID")
    return obj


def get_profile(provider: str) -> Profile:
    if not isinstance(provider, str) or not re.fullmatch(r"[A-Za-z0-9._:/+-]{1,110}", provider):
        raise FramingError("PROVIDER_INVALID")
    config = _load("profiles.yaml")
    record = config["providers"].get(provider.split("/", 1)[0], config["default"])
    if set(record) != {"level", "dictionary", "max_length", "max_format_retries",
                       "command_format_retries", "format_failures"}:
        raise FramingError("PROFILE_SCHEMA_INVALID")
    level, dictionary, limit, retries = (record["level"], record["dictionary"],
                                         record["max_length"], record["max_format_retries"])
    command_retries = record["command_format_retries"]
    failures = record["format_failures"]
    lexicon = _load("lexicon.yaml")["dictionaries"]
    if (type(level) is not int or level not in WRAPPERS or type(limit) is not int
            or not 1 <= limit <= 8192 or dictionary not in lexicon
            or type(retries) is not int or not 0 <= retries <= 1
            or type(command_retries) is not int or not 0 <= command_retries <= 2
            or type(failures) is not int or not 0 <= failures <= 100000):
        raise FramingError("PROFILE_UNSAFE")
    # Only format failures can raise the initial command level; safety
    # refusals are never recorded as format failures or retried.
    if provider.split("/", 1)[0] != "local" and failures >= 3:
        level = min(3, level + 1)
    return Profile(level, dictionary, limit, retries, command_retries, failures)


def check_wrapper(level: int, dictionary: str = "neutral") -> None:
    if type(level) is not int or level not in WRAPPERS:
        raise FramingError("FRAME_LEVEL_INVALID")
    lexicon = _load("lexicon.yaml")["dictionaries"].get(dictionary)
    if not isinstance(lexicon, dict):
        raise FramingError("FRAME_DICTIONARY_UNKNOWN")
    wrapper = "\n".join(WRAPPERS[level])
    if len(WRAPPERS[level]) > 8:
        raise FramingError("FRAME_WRAPPER_TOO_LONG")
    # This checks the STATIC wrapper only, never hides or rewrites brief content.
    if level == 2:
        for term in lexicon["wrapper_forbidden_terms"]:
            if re.search(r"(?i)(?<!\w)" + re.escape(term) + r"(?!\w)", wrapper):
                raise FramingError("WRAPPER_NONNEUTRAL")


def frame(brief: str, level: int, provider: str) -> str:
    profile = get_profile(provider)
    check_wrapper(level, profile.dictionary)
    if (not isinstance(brief, str) or not brief or len(brief) > profile.max_length
            or START in brief or END in brief or "\x00" in brief):
        raise FramingError("FRAME_BRIEF_INVALID")
    if level == 0:
        return brief + "\n" + CONTRACT
    wrapper = "\n".join(WRAPPERS[level])
    prefix = (wrapper + "\n" if wrapper else "")
    return prefix + START + "\n" + brief + "\n" + END + "\n" + CONTRACT


def unframe(framed: str, level: int, provider: str) -> str:
    """Strictly extract untouched data, then compare with its canonical frame."""
    if not isinstance(framed, str) or len(framed) > 16384:
        raise FramingError("FRAME_NOT_CANONICAL")
    if level == 0:
        suffix = "\n" + CONTRACT
        if not framed.endswith(suffix):
            raise FramingError("FRAME_NOT_CANONICAL")
        brief = framed[:-len(suffix)]
    else:
        if framed.count(START) != 1 or framed.count(END) != 1:
            raise FramingError("FRAME_BOUNDARIES_INVALID")
        begin = framed.index(START) + len(START) + 1
        end = framed.index("\n" + END)
        brief = framed[begin:end]
    if frame(brief, level, provider) != framed:
        raise FramingError("FRAME_NOT_CANONICAL")
    return brief
