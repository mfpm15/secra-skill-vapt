"""Strict response-to-argv parser. No subprocess or shell calls."""
from __future__ import annotations

import re
import shlex

from .command import CommandSpec
from .template import FramingError

_INTRO = re.compile(
    r"(?i)^\s*(?:berikut(?:\s+adalah|\s+perintahnya)?(?:\s+perintahnya)?"
    r"|here(?:\s+is|'s)\s+the\s+command|command\s*:|perintah\s*:)\s*:?\s*$"
)
_NUMBER = re.compile(r"^\s*(?:\d{1,2}\s*[.)]|[-*])\s+")
_FENCE_OPEN = re.compile(r"(?i)^\x60{3}(?:bash|sh|shell)?\s*$")
_FENCE_CLOSE = re.compile(r"^\x60{3}\s*$")
_ASSUMPTION = re.compile(r"^\[ASUMSI\](?:\s.*)?$")
_RISK = re.compile(r"^RISK_CLASS=R[34](?:\s.*)?$")


class CommandStripError(FramingError):
    pass


def strip_command(response: str, manifest: CommandSpec) -> list[str]:
    """Extract one argv list matching the reviewed manifest exactly."""
    if not isinstance(manifest, CommandSpec):
        raise CommandStripError("COMMAND_MANIFEST_REQUIRED")
    if not isinstance(response, str) or len(response) > 16384 or not response.strip():
        raise CommandStripError("COMMAND_RESPONSE_INVALID")
    if response.strip() == "UNRESOLVED_PLACEHOLDER":
        raise CommandStripError("UNRESOLVED_PLACEHOLDER")
    lines = [line.strip() for line in response.strip().splitlines() if line.strip()]
    if len(lines) > 16:
        raise CommandStripError("COMMAND_RESPONSE_TOO_MANY_LINES")
    from .detect import detect
    if detect(response).reason == "SAFETY_REFUSAL":
        raise CommandStripError("COMMAND_SAFETY_REFUSAL")
    if lines and _INTRO.fullmatch(lines[0]):
        lines.pop(0)
    while lines and _ASSUMPTION.fullmatch(lines[-1]):
        lines.pop()
    if lines and _RISK.fullmatch(lines[-1]):
        marker = lines.pop()
        if manifest.risk_class not in {"R3", "R4"} or not marker.startswith(
                "RISK_CLASS=" + manifest.risk_class):
            raise CommandStripError("COMMAND_RISK_MISMATCH")
    if lines and _FENCE_OPEN.fullmatch(lines[0]):
        lines.pop(0)
        if not lines or not _FENCE_CLOSE.fullmatch(lines[-1]):
            raise CommandStripError("COMMAND_FENCE_UNBALANCED")
        lines.pop()
    if len(lines) != 1:
        raise CommandStripError("COMMAND_NOT_SINGLE_LINE")
    command = _NUMBER.sub("", lines[0], count=1).strip()
    if (len(command) >= 2 and
            ((command.startswith('"') and command.endswith('"'))
             or (command.startswith("'") and command.endswith("'")))):
        command = command[1:-1]
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as exc:
        raise CommandStripError("COMMAND_QUOTING_INVALID") from exc
    if tuple(tokens) not in manifest.approved:
        raise CommandStripError("COMMAND_ARGV_OUTSIDE_MANIFEST")
    return tokens
