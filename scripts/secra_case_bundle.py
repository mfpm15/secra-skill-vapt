#!/usr/bin/env python3
"""Export or restore an encrypted per-engagement case bundle, offline only.

Passphrase is prompted on a trusted local TTY and never passed as a CLI
argument or forwarded to an LLM. Restores into a NEW folder only.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.case_bundle import BundleError, create_bundle, restore_bundle, write_bundle
from app.loop.store import TaskError, TaskStore


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("export", "restore"))
    parser.add_argument("--task-id", help="Existing authorized task UUID (required for export)")
    parser.add_argument("--data-dir", type=Path, default=Path(
        os.environ.get("SECRA_DATA_DIR", str(ROOT / "data"))))
    parser.add_argument("--bundle", type=Path, required=True,
                        help="New .secra-case ciphertext for export, existing for restore")
    parser.add_argument("--destination", type=Path,
                        help="New offline restore directory (restore only)")
    args = parser.parse_args()
    try:
        if args.command == "export":
            if not args.task_id or args.destination:
                raise BundleError("BUNDLE_EXPORT_OPTIONS")
            db = args.data_dir / "agent-events.sqlite3"
            if db.is_symlink() or not db.is_file():
                raise BundleError("BUNDLE_DATABASE_MISSING")
            secret = getpass.getpass("Case bundle passphrase (16+ characters): ")
            repeat = getpass.getpass("Repeat passphrase: ")
            if secret != repeat:
                raise BundleError("BUNDLE_PASSPHRASE_MISMATCH")
            content = create_bundle(TaskStore(args.data_dir), args.task_id, secret)
            write_bundle(args.bundle.expanduser(), content)
            print(json.dumps({
                "status": "encrypted_case_export_created",
                "task_id": args.task_id, "bundle": str(args.bundle),
                "case_is_operator_private": True,
            }))
        else:
            if args.task_id or not args.destination:
                raise BundleError("BUNDLE_RESTORE_OPTIONS")
            bundle = args.bundle.expanduser()
            if (bundle.is_symlink() or not bundle.is_file()
                    or bundle.stat().st_size > 96 * 1024 * 1024 + 1024):
                raise BundleError("BUNDLE_INPUT_UNSAFE")
            secret = getpass.getpass("Case bundle passphrase: ")
            result = restore_bundle(
                bundle.read_bytes(), secret, args.destination.expanduser())
            print(json.dumps(result))
        return 0
    except (OSError, TaskError, BundleError, ValueError) as exc:
        print("SECRA case bundle error: " + type(exc).__name__
              + (": " + str(exc) if isinstance(exc, BundleError) else ""),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
