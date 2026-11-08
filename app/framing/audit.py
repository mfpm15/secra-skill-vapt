"""Local only, append-only audit of the SANITIZED pre/post framing bytes.

Do not log original unmasked customer prompts, raw evidence, provider keys,
responses, tool commands, or vault mappings. The value named pre_frame_masked
is the exact canonical Phase-1-approved model metadata (not user raw text).
"""
from __future__ import annotations

import json
import os
import stat
import uuid
from pathlib import Path

from app.masking import guard_mask
from .template import unframe, FramingError


class FramingAuditError(RuntimeError):
    pass


def record_framing(root: str | Path, *, task_id: str, provider: str, level: int,
                   masked_brief: str, framed_prompt: str,
                   result_reason: str = "PENDING",
                   outcome: str = "prepared") -> Path:
    if outcome not in {"prepared", "completed", "refused", "no_artifact", "failed"}:
        raise FramingAuditError("AUDIT_OUTCOME_INVALID")
    if result_reason not in {"PENDING", "ARTIFACT_PRESENT", "SAFETY_REFUSAL",
                             "EMPTY_OR_INVALID", "CLARIFICATION_ONLY",
                             "CONSULTATIVE_RESPONSE", "NO_ARTIFACT", "PROVIDER_ERROR"}:
        raise FramingAuditError("AUDIT_REASON_INVALID")
    try:
        uid = str(uuid.UUID(task_id))
        if uid != task_id:
            raise ValueError("noncanonical UUID")
        # Validate raw canonical Phase-1 schema before writing any string.
        checked, _ = guard_mask(masked_brief, for_llm=True)
        if checked != masked_brief or unframe(framed_prompt, level, provider) != masked_brief:
            raise FramingAuditError("AUDIT_UNSAFE_PROMPT")
    except (ValueError, TypeError, FramingError) as exc:
        raise FramingAuditError("AUDIT_UNSAFE_PROMPT") from exc
    root = Path(root)
    if root.is_symlink():
        raise FramingAuditError("AUDIT_UNSAFE_DIRECTORY")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    path = root / (uid + ".jsonl")
    record = {
        "task_id": uid, "provider": provider, "level": level,
        "pre_frame_masked": masked_brief,
        "framed_prompt": framed_prompt, "result_reason": result_reason,
        "outcome": outcome,
    }
    line = (json.dumps(record, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
    try:
        fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600:
                raise FramingAuditError("AUDIT_UNSAFE_FILE")
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise FramingAuditError("AUDIT_WRITE_FAILED") from exc
    return path
