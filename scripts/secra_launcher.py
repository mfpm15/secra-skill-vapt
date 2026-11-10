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
LEGACY_V1_SCRIPT = "#!/bin/sh\n# SECRA_MANAGED_OPENCODE_LAUNCHER_V1\nif ! command -v opencode >/dev/null 2>&1; then\n  printf 'SECRA: OpenCode executable not found in PATH.\\n' >&2\n  exit 127\nfi\nexec opencode --agent secra \"$@\"\n"
LEGACY_MINI_SCRIPT = "#!/bin/sh\n# SECRA_MANAGED_OPENCODE_LAUNCHER_V1\nif ! command -v opencode >/dev/null 2>&1; then\n  printf 'SECRA: OpenCode executable not found in PATH.\\n' >&2\n  exit 127\nfi\nexec opencode mini --agent secra \"$@\"\n"
SCRIPT = "#!/bin/sh\n# SECRA_MANAGED_OPENCODE_LAUNCHER_V1\nif ! command -v opencode >/dev/null 2>&1; then\n  printf 'SECRA: OpenCode executable not found in PATH.\\n' >&2\n  exit 127\nfi\n# OpenCode v2 full TUI does not accept --agent. Choose SECRA only for\n# this child process; preserve provider/model and any existing inline config.\nif [ \"${OPENCODE_CONFIG_CONTENT+x}\" = x ]; then\n  if ! command -v python3 >/dev/null 2>&1; then\n    printf 'SECRA: python3 required to preserve inline OpenCode configuration.\\n' >&2\n    exit 2\n  fi\n  OPENCODE_CONFIG_CONTENT=\"$(python3 -c 'import json, os; cfg=json.loads(os.environ[\"OPENCODE_CONFIG_CONTENT\"]);\nif not isinstance(cfg, dict): raise ValueError(\"Invalid inline config\");\ncfg[\"default_agent\"]=\"secra\"; print(json.dumps(cfg))')\" || exit 2\nelse\n  OPENCODE_CONFIG_CONTENT='{\"default_agent\":\"secra\"}'\nfi\nexport OPENCODE_CONFIG_CONTENT\nexec opencode \"$@\"\n"

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
