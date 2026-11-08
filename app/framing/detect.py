"""Conservative output classifier: refusals are terminal, never auto-reframed."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

REFUSAL = re.compile(r"(?i)\b(?:sorry|maaf|cannot assist|can't help|tidak dapat membantu|tidak bisa membantu|i must decline)\b")
VAGUE = re.compile(r"(?i)\b(?:secara umum|berikut adalah|in general|as an ai|sebagai ai)\b")
ASKING = re.compile(r"(?i)(?:\?\s*$|\b(?:bisakah anda|apakah anda|could you please|can you provide)\b)")
CHECKLIST = re.compile(r"(?m)^\s*(?:[-*]\s+\[[ xX]\]|\d{1,2}[.)]\s+)")
CODE = re.compile(r"(?m)^```[a-zA-Z0-9_-]*\s*$")


@dataclass(frozen=True)
class Detection:
    non_artifact: bool
    reason: str
    retryable: bool


def detect(text: str, *, provider_refusal: bool = False) -> Detection:
    if provider_refusal:
        return Detection(True, "SAFETY_REFUSAL", False)
    if not isinstance(text, str) or len(text) > 200000 or not text.strip():
        return Detection(True, "EMPTY_OR_INVALID", True)
    value = text.strip()
    if REFUSAL.search(value):
        return Detection(True, "SAFETY_REFUSAL", False)
    if CHECKLIST.search(value) or CODE.search(value):
        return Detection(False, "ARTIFACT_PRESENT", False)
    try:
        obj = json.loads(value)
        if isinstance(obj, dict) and "artifact" in obj:
            return Detection(False, "ARTIFACT_PRESENT", False)
    except (ValueError, TypeError):
        pass
    if ASKING.search(value):
        return Detection(True, "CLARIFICATION_ONLY", True)
    if VAGUE.search(value):
        return Detection(True, "CONSULTATIVE_RESPONSE", True)
    return Detection(True, "NO_ARTIFACT", True)
