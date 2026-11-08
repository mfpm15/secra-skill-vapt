"""Deterministic command framing; never authorizes or launches a process.

Command proposals are not execution grants. Only a separately authorized,
reviewed dispatcher may consume the exact parsed argv after scope/approval
checks. Model-facing argv contains placeholders, never rehydrated host secrets.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Sequence

from .template import FramingError, get_profile, _load

COMMAND_START = "---SECRA-COMMAND-START---"
COMMAND_END = "---SECRA-COMMAND-END---"
COMMAND_CONTRACT = (
    "OUTPUT CONTRACT: Return a command block, one command per line, without prose. "
    "Use only tokens authorized by the reviewed command manifest. "
    "For noncritical uncertainty, add one [ASUMSI] line without altering the argv. "
    "Return UNRESOLVED_PLACEHOLDER and stop if any placeholder is unknown. "
    "For R3 or R4 return the risk class on the final line; execution requires explicit approval."
)
COMMAND_WRAPPERS = {
    0: (),
    1: (
        "Task: produce the exact command argv for the approved dispatcher.",
        "Keep the tool and arguments in their original order.",
    ),
    2: (
        "Context: authorized verification task with a pre-reviewed command.",
        "Objective: return a machine-readable command artifact for the trusted dispatcher.",
        "Use the supplied command tokens exactly; changes need manifest permission.",
        "Target placeholders refer to local assets and must stay unresolved here.",
        "The dispatcher independently checks scope, approvals and runtime isolation.",
    ),
    3: (),
}
KNOWN_TOOLS = frozenset({"nmap", "curl"})


@dataclass(frozen=True)
class CommandSpec:
    tool: str
    argv: tuple[str, ...]
    purpose: str
    risk_class: str
    variants: tuple[tuple[str, ...], ...] = ()

    def __post_init__(self):
        if self.tool not in KNOWN_TOOLS:
            raise FramingError("COMMAND_TOOL_NOT_REVIEWED")
        if not isinstance(self.argv, tuple) or not 2 <= len(self.argv) <= 32:
            raise FramingError("COMMAND_ARGV_INVALID")
        if self.argv[0] not in {self.tool, "/usr/bin/" + self.tool}:
            raise FramingError("COMMAND_BINARY_MISMATCH")
        if not isinstance(self.purpose, str) or not 1 <= len(self.purpose) <= 160:
            raise FramingError("COMMAND_PURPOSE_INVALID")
        if any(ch in self.purpose for ch in ("\n", "\r", "\x00", "<", ">")):
            raise FramingError("COMMAND_PURPOSE_INVALID")
        if self.risk_class not in {"R0", "R1", "R2", "R3", "R4"}:
            raise FramingError("COMMAND_RISK_INVALID")
        if len(self.variants) > 8:
            raise FramingError("COMMAND_VARIANTS_INVALID")
        for candidate in (self.argv, *self.variants):
            if (not isinstance(candidate, tuple) or not candidate
                    or candidate[0] != self.argv[0]):
                raise FramingError("COMMAND_VARIANTS_INVALID")
            for token in candidate:
                if not isinstance(token, str) or not 1 <= len(token) <= 512:
                    raise FramingError("COMMAND_TOKEN_INVALID")
                if any(x in token for x in ("\x00", "\n", "\r", chr(96), "$(", ";", "&&", "||", "|", "\x1b")):
                    raise FramingError("COMMAND_SHELL_METACHARACTERS")
                if re.search(r"(?i)(?:authorization:|bearer\s|api[_-]?key|password=)", token):
                    raise FramingError("COMMAND_SECRET_SUSPECTED")
                for ip in re.findall(r"(?<![A-Za-z0-9])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9])", token):
                    try:
                        ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    raise FramingError("COMMAND_RAW_TARGET_DENIED")
                if re.search(r"(?i)https?://(?!<HOST_[1-9][0-9]*>[/:\s]|<IP_[1-9][0-9]*>[/:\s])", token):
                    raise FramingError("COMMAND_RAW_URL_DENIED")
                for placeholder in re.findall(r"<[^<>\s]{1,100}>", token):
                    if not re.fullmatch(r"<(?:HOST|IP)_[1-9][0-9]*>", placeholder):
                        raise FramingError("COMMAND_PLACEHOLDER_UNKNOWN")

    @property
    def approved(self) -> tuple[tuple[str, ...], ...]:
        return (self.argv, *self.variants)


def _check_command_wrapper(level: int, dictionary: str) -> None:
    if type(level) is not int or level not in COMMAND_WRAPPERS:
        raise FramingError("COMMAND_LEVEL_INVALID")
    lines = COMMAND_WRAPPERS[level]
    if len(lines) > 8:
        raise FramingError("COMMAND_WRAPPER_TOO_LONG")
    terms = _load("lexicon.yaml")["dictionaries"][dictionary]["wrapper_forbidden_terms"]
    if level == 2:
        narration = "\n".join(lines)
        for word in terms:
            if re.search(r"(?i)(?<!\w)" + re.escape(word) + r"(?!\w)", narration):
                raise FramingError("COMMAND_WRAPPER_NONNEUTRAL")


def frame_command(tool: str, argv: Sequence[str], level: int, provider: str,
                  *, purpose: str = "Verify an authorized service endpoint",
                  risk_class: str = "R2") -> str:
    """Preserve argv by JSON-encoding the original list; no paraphrases or shell."""
    spec = CommandSpec(tool, tuple(argv), purpose, risk_class)
    profile = get_profile(provider)
    _check_command_wrapper(level, profile.dictionary)
    data = json.dumps(list(spec.argv), ensure_ascii=True, separators=(",", ":"))
    if len(data) > profile.max_length:
        raise FramingError("COMMAND_TOO_LARGE")
    prefix = "\n".join(COMMAND_WRAPPERS[level])
    lines = ("TOOL: " + tool + "\n"
             + "PURPOSE: " + spec.purpose + "\n"
             + "RISK: " + spec.risk_class + "\n"
             + COMMAND_START + "\n" + data + "\n" + COMMAND_END)
    suffix = COMMAND_CONTRACT
    if risk_class in {"R3", "R4"}:
        suffix += "\nRISK_CLASS=" + risk_class + " (approval required before execution)"
    return ((prefix + "\n") if prefix else "") + lines + "\n" + suffix
