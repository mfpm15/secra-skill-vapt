#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"

if [[ ! -x "$PYTHON" ]]; then
  echo "SECRA MCP unavailable: create .venv and install requirements.txt first." >&2
  exit 2
fi

cd "$ROOT"
exec "$PYTHON" -m app.mcp.server --transport stdio
