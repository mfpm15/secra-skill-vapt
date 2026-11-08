"""Bounded *format repair* only. Safety refusals never trigger retries.

A task has at most two actual model calls, no repeated levels, no policy bypass.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .detect import Detection


@dataclass
class FormatLadder:
    initial_level: int
    max_attempts: int = 2
    tried: list[int] = field(default_factory=list)
    status: str = "created"

    def __post_init__(self):
        if type(self.initial_level) is not int or not 0 <= self.initial_level <= 3:
            raise ValueError("LADDER_LEVEL_INVALID")
        if type(self.max_attempts) is not int or not 1 <= self.max_attempts <= 2:
            raise ValueError("LADDER_ATTEMPTS_INVALID")

    def next_level(self, previous: Detection | None = None) -> int | None:
        if self.status in {"completed", "exhausted", "refused"}:
            return None
        if previous is not None:
            if not self.tried:
                raise ValueError("LADDER_NO_PREVIOUS_ATTEMPT")
            if previous.reason == "SAFETY_REFUSAL" or not previous.retryable and previous.non_artifact:
                self.status = "refused"
                return None
            if not previous.non_artifact:
                self.status = "completed"
                return None
        elif self.tried:
            raise ValueError("LADDER_RESULT_REQUIRED")
        if len(self.tried) >= self.max_attempts:
            self.status = "exhausted"
            return None
        candidate = min(3, self.initial_level + len(self.tried))
        if candidate in self.tried:
            self.status = "exhausted"
            return None
        self.tried.append(candidate)
        self.status = "running"
        return candidate
