"""Install a tiny user-owned SECRA OpenCode launcher.

No changes to shell profile, provider configuration, models or working dir.
Never overwrite an unrelated executable, even with --replace.
"""
from __future__ import annotations

import os
import shutil
import stat
import tempfile
from pathlib import Path

MARKER = "# SECRA_MANAGED_OPENCODE_LAUNCHER_V1"
SCRIPT = (
    "#!/bin/sh\n" + MARKER + "\n"
    "if ! command -v opencode >/dev/null 2>&1; then\n"
    "  printf 'SECRA: OpenCode executable not found in PATH.\\n' >&2\n"
    "  exit 127\n"
    "fi\n"
    'exec opencode --agent secra "$@"\n'
)


class LauncherError(ValueError):
    pass


def install(destination: Path, *, dry_run: bool = False,
            replace: bool = False) -> str:
    destination = Path(destination).expanduser()
    if destination.is_symlink() or destination.parent.is_symlink():
        raise LauncherError("LAUNCHER_PATH_SYMLINK")
    if destination.exists():
        if not destination.is_file() or destination.is_symlink():
            raise LauncherError("LAUNCHER_INVALID_EXISTING_ENTRY")
        previous = destination.read_text(encoding="utf-8")
        if previous == SCRIPT:
            return "UNCHANGED secra launcher"
        if MARKER not in previous or not replace:
            raise LauncherError("LAUNCHER_EXISTS_AND_IS_NOT_REPLACEABLE")
    if dry_run:
        return "DRY-RUN secra launcher " + str(destination)
    destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if destination.parent.is_symlink():
        raise LauncherError("LAUNCHER_PARENT_SYMLINK")
    if destination.exists() and replace:
        backup = destination.with_name(destination.name + ".secra-previous")
        if backup.exists() or backup.is_symlink():
            raise LauncherError("LAUNCHER_BACKUP_ALREADY_EXISTS")
        shutil.copy2(destination, backup)
        backup.chmod(0o600)
    fd, staging = tempfile.mkstemp(prefix=".secra-launch-", dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(SCRIPT)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(staging, 0o700)
        os.replace(staging, destination)
    finally:
        if os.path.exists(staging):
            os.unlink(staging)
    return "INSTALLED secra launcher " + str(destination)


def verify(destination: Path) -> None:
    path = Path(destination).expanduser()
    if path.is_symlink() or not path.is_file():
        raise LauncherError("LAUNCHER_NOT_INSTALLED")
    if path.read_text(encoding="utf-8") != SCRIPT:
        raise LauncherError("LAUNCHER_UNRECOGNIZED_OR_CHANGED")
    if not (stat.S_IMODE(path.stat().st_mode) & 0o100):
        raise LauncherError("LAUNCHER_NOT_EXECUTABLE")
