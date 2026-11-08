"""Offline command proposal session: model text is untrusted, never executed.

A caller can supply a generate(prompt)->str callback only after independently
deciding it is authorized to send the placeholder-only prompt to that model.
The callback is not a privileged tool runner, and no process is started here.
"""
from __future__ import annotations

import json
import os
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .command import CommandSpec, frame_command
from .strip import CommandStripError, strip_command
from .detect import detect
from .ladder import FormatLadder
from .template import get_profile


@dataclass(frozen=True)
class CommandPlan:
    task_id: str
    status: str
    argv: list[str] | None
    levels: tuple[int, ...]
    reason: str
    trace_path: Path
    risk_class: str

    @property
    def dispatch_eligible(self) -> bool:
        # Even for R2 the *separate* dispatcher still needs a valid scope,
        # worker lease and kernel fence; this property only blocks R3/R4.
        return self.status == "prepared" and self.risk_class in {"R0", "R1", "R2"}


def _audit(root: Path, task_id: str, event: dict) -> Path:
    if root.is_symlink():
        raise ValueError("COMMAND_AUDIT_SYMLINK")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    path = root / (task_id + ".jsonl")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600:
            raise ValueError("COMMAND_AUDIT_PERMISSIONS")
        data = json.dumps(event, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
        if os.write(fd, data) != len(data):
            raise OSError("COMMAND_AUDIT_PARTIAL_WRITE")
        os.fsync(fd)
    finally:
        os.close(fd)
    return path


def prepare_command(manifest: CommandSpec, provider: str, generate: Callable[[str], str],
                    audit_root: str | Path, *, task_id: str | None = None,
                    previous_summary: str | None = None) -> CommandPlan:
    """A bounded *format* loop; no retry after refusal and no synthetic argv."""
    if not isinstance(manifest, CommandSpec) or not callable(generate):
        raise ValueError("COMMAND_MANIFEST_OR_CALLBACK_INVALID")
    tid = str(uuid.uuid4()) if task_id is None else str(uuid.UUID(task_id))
    if tid != (task_id or tid):
        raise ValueError("COMMAND_TASK_ID_INVALID")
    profile = get_profile(provider)
    ladder = FormatLadder(profile.level,
                          max_attempts=1 + profile.command_format_retries)
    root = Path(audit_root)
    previous = None
    reason = "NO_VALID_COMMAND"
    trace_path = root / (tid + ".jsonl")
    while True:
        level = ladder.next_level(previous)
        if level is None:
            break
        framed = frame_command(manifest.tool, manifest.argv, level, provider,
                               purpose=manifest.purpose, risk_class=manifest.risk_class,
                               previous_summary=previous_summary,
                               registered_placeholders=manifest.registered_placeholders)
        _audit(root, tid, {
            "task_id": tid, "status": "requested", "level": level, "provider": provider,
            "masked_argv": list(manifest.argv), "framed_command": framed,
            "risk_class": manifest.risk_class,
        })
        response = generate(framed)
        if not isinstance(response, str):
            response = ""
        signal = detect(response)
        if signal.reason == "SAFETY_REFUSAL":
            reason = signal.reason
            ladder.next_level(signal)
            _audit(root, tid, {"task_id": tid, "status": "refused",
                               "level": level, "reason": reason})
            return CommandPlan(tid, "refused", None, tuple(ladder.tried),
                               reason, trace_path, manifest.risk_class)
        try:
            parsed = strip_command(response, manifest)
        except CommandStripError as exc:
            reason = str(exc)
            # Only formatting failures are retryable. Unknown placeholders
            # and explicit refusals are terminal, without fallback commands.
            if reason in {"UNRESOLVED_PLACEHOLDER", "COMMAND_SAFETY_REFUSAL"}:
                _audit(root, tid, {"task_id": tid, "status": "blocked",
                                   "level": level, "reason": reason})
                return CommandPlan(tid, "blocked", None, tuple(ladder.tried),
                                   reason, trace_path, manifest.risk_class)
            from .detect import Detection
            previous = Detection(True, "NO_VALID_COMMAND", True)
            _audit(root, tid, {"task_id": tid, "status": "format_error",
                               "level": level, "reason": reason})
            continue
        final_status = ("approval_required" if manifest.risk_class in {"R3", "R4"}
                        else "prepared")
        _audit(root, tid, {"task_id": tid, "status": final_status,
                           "level": level, "validated_argv": parsed,
                           "risk_class": manifest.risk_class, "reason": "MANIFEST_MATCH"})
        return CommandPlan(tid, final_status, parsed, tuple(ladder.tried),
                           "MANIFEST_MATCH", trace_path, manifest.risk_class)
    _audit(root, tid, {"task_id": tid, "status": "exhausted",
                       "levels": ladder.tried, "reason": reason,
                       "manual_copy_argv": list(manifest.argv)})
    return CommandPlan(tid, "exhausted", None, tuple(ladder.tried),
                       reason, trace_path, manifest.risk_class)
