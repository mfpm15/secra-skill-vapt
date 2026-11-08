"""Deterministic output-oriented framing, separate from Phase-1 PII masking."""
from .template import frame, unframe, get_profile, check_wrapper, FramingError
from .detect import detect, Detection
from .ladder import FormatLadder

__all__ = ["frame", "unframe", "get_profile", "check_wrapper", "FramingError",
           "detect", "Detection", "FormatLadder"]
