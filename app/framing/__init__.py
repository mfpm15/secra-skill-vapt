"""Deterministic output-oriented framing, separate from Phase-1 PII masking."""
from .template import frame, unframe, get_profile, check_wrapper, FramingError
from .detect import detect, Detection
from .ladder import FormatLadder

from .command import frame_command, CommandSpec, COMMAND_CONTRACT
from .strip import strip_command, CommandStripError
from .command_session import prepare_command, CommandPlan

__all__ = ["frame_command", "CommandSpec", "COMMAND_CONTRACT",
           "strip_command", "CommandStripError", "prepare_command", "CommandPlan","frame", "unframe", "get_profile", "check_wrapper", "FramingError",
           "detect", "Detection", "FormatLadder"]
