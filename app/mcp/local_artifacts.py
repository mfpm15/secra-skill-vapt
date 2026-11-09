"""Six genuine, read-only local Kali artifact tools for SECRA MCP.

The only permitted input is an operator-provided regular file under the
private engagement/03-evidence/analysis-input/ folder. No target IP, URLs,
shell arguments, arbitrary paths or network tools accepted. Raw output is
sealed by the dispatcher, not sent to the external model.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import resource
import shutil
import stat
import subprocess
from pathlib import Path

from app.workspace import WorkspaceManager

MAX_INPUT = 16 * 1024 * 1024
MAX_STDOUT = 6 * 1024 * 1024
NAMES = {
    "artifact.sha256": None,
    "artifact.file_type": ("file", ("--brief", "--mime-type", "--")),
    "artifact.strings": ("strings", ("-a", "-n", "8", "--")),
    "artifact.elf_header": ("readelf", ("-h", "--")),
    "artifact.object_summary": ("objdump", ("-f", "--")),
    "artifact.metadata": ("exiftool", ("-j", "-G", "--")),
}
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,139}$")
MIME = re.compile(r"^[a-z0-9.+_-]+/[a-z0-9.+_-]+$")


class ArtifactDenied(ValueError):
    pass


def _file(root: Path, task_id: str, name: str) -> Path:
    if not isinstance(name, str) or not SAFE_NAME.fullmatch(name):
        raise ArtifactDenied("ARTIFACT_NAME_INVALID")
    relative = Path(name)
    if (relative.is_absolute() or any(part in {".", ".."} for part in relative.parts)
            or name.startswith(".")):
        raise ArtifactDenied("ARTIFACT_TRAVERSAL_DENIED")
    engagement = WorkspaceManager(root / "engagements").require(task_id)
    base = engagement / "03-evidence" / "analysis-input"
    if not base.is_dir() or base.is_symlink():
        raise ArtifactDenied("ARTIFACT_INPUT_DIRECTORY_MISSING")
    source = base / relative
    if source.is_symlink() or not source.is_file():
        raise ArtifactDenied("ARTIFACT_NOT_REGULAR_FILE")
    cursor = source.parent
    while cursor != base:
        if cursor.is_symlink() or not cursor.is_dir():
            raise ArtifactDenied("ARTIFACT_ANCESTOR_SYMLINK")
        cursor = cursor.parent
    if not source.resolve().is_relative_to(base.resolve()):
        raise ArtifactDenied("ARTIFACT_OUTSIDE_ENGAGEMENT")
    info = source.stat()
    if (not stat.S_ISREG(info.st_mode) or
            not 0 < info.st_size <= MAX_INPUT):
        raise ArtifactDenied("ARTIFACT_SIZE_OR_TYPE_DENIED")
    return source


def is_available(tool: str) -> bool:
    if tool not in NAMES:
        return False
    if tool == "artifact.sha256":
        return True
    binary = shutil.which(NAMES[tool][0])
    if binary is None:
        return False
    path = Path(binary).resolve()
    try:
        st = path.stat()
    except OSError:
        return False
    return (path.is_file() and st.st_uid == 0
            and not bool(stat.S_IMODE(st.st_mode) & 0o022))


def _limit_process() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (6, 7))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_STDOUT, MAX_STDOUT))


def inspect(root: Path, task_id: str, tool: str, filename: str) -> tuple[bytes, str]:
    if tool not in NAMES:
        raise ArtifactDenied("UNREVIEWED_ARTIFACT_TOOL")
    path = _file(Path(root), task_id, filename)
    hasher = hashlib.sha256()
    with path.open("rb") as reader:
        while True:
            block = reader.read(65536)
            if not block:
                break
            hasher.update(block)
    digest = hasher.hexdigest()
    if tool == "artifact.sha256":
        result = json.dumps({"sha256": digest, "bytes": path.stat().st_size,
                             "network_calls": 0}, sort_keys=True).encode()
        return result, "Reviewed local artifact SHA-256: " + digest[:20] + " (full hash sealed)."

    if not is_available(tool):
        raise ArtifactDenied("KALI_ARTIFACT_BINARY_MISSING_OR_UNTRUSTED")
    program, fixed = NAMES[tool]
    binary = str(Path(shutil.which(program)).resolve())
    # No shell, no aliases, no LLM-controlled flags, no network target.
    args = [binary, *fixed, str(path)]
    try:
        completed = subprocess.run(
            args, input=b"", capture_output=True, timeout=12,
            check=False, start_new_session=True, preexec_fn=_limit_process,
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
                 "LANG": "C", "LC_ALL": "C"},
            cwd=str(path.parent),
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise ArtifactDenied("KALI_ARTIFACT_TOOL_TIMEOUT_OR_FAILURE") from exc
    if completed.returncode != 0:
        raise ArtifactDenied("KALI_ARTIFACT_TOOL_NONZERO_EXIT")
    raw = completed.stdout
    if len(raw) > MAX_STDOUT:
        raise ArtifactDenied("KALI_ARTIFACT_OUTPUT_LIMIT")
    if tool == "artifact.file_type":
        mime = raw.decode("utf-8", "replace").strip()
        detail = ("MIME " + mime) if MIME.fullmatch(mime) else "file type available in sealed artifact"
    else:
        detail = "raw analysis sealed locally"
    safe = ("Reviewed local " + program + " inspection completed; " + detail
            + "; source SHA-256 " + digest[:16] + "; output bytes " + str(len(raw))
            + ". No finding auto-verified.")
    return raw or b"NO_OUTPUT", safe
