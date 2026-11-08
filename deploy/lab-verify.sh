#!/usr/bin/env bash
# Kali-only privileged fence witness runner. Never creates a PASS attestation.
set -euo pipefail
umask 077

REQUIRE_STRICT=0
if [[ "${1:-}" == "--require-strict" ]]; then
  REQUIRE_STRICT=1
  shift
fi
if (( $# != 0 )); then
  printf 'Usage: deploy/lab-verify.sh [--require-strict]\n' >&2
  exit 2
fi
if (( REQUIRE_STRICT )) && [[ "${SECRA_FENCE_MODE:-strict}" != "strict" ]]; then
  printf 'LAB_GATE_FAILED: require-strict refuses fence mode other than strict\n' >&2
  exit 2
fi
if (( EUID != 0 )); then
  printf 'LAB_GATE_FAILED: must be run as root on an authorized Kali lab VM\n' >&2
  exit 2
fi
if [[ ! -f /etc/os-release ]]; then
  printf 'LAB_GATE_FAILED: missing OS release evidence\n' >&2
  exit 2
fi
# shellcheck disable=SC1091
source /etc/os-release
if [[ "${ID:-}" != "kali" ]] || [[ ! -d /run/systemd/system ]]; then
  printf 'LAB_GATE_FAILED: Kali Linux with systemd PID1 required\n' >&2
  exit 2
fi
for command in python3 bpftool systemctl systemd-run pgrep; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'LAB_GATE_FAILED: missing prerequisite %s\n' "$command" >&2
    exit 2
  fi
done

RUN_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
EVIDENCE="/var/lib/secra/evidence/fence-lab/${RUN_ID}"
install -d -m 0700 -o 0 -g 0 "$EVIDENCE"
export SECRA_LAB_PROFILE="authorized-kali-vm"
export SECRA_FENCE_LAB_EVIDENCE="$EVIDENCE"
export SECRA_FENCE_MODE="strict"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd -- "$ROOT"

printf 'Kali fence witness directory: %s\n' "$EVIDENCE"
printf 'Executing all 13 mandatory privileged kernel cases...\n'
if python3 -m pytest tests/fence/test_lab.py -m lab -q -ra \
   --junitxml="$EVIDENCE/pytest.xml" > "$EVIDENCE/pytest.log" 2>&1; then
  printf 'Pytest returned zero. Verifying independent evidence...\n'
else
  status=$?
  printf 'LAB_GATE_FAILED: privileged kernel tests returned %s, see %s\n' "$status" "$EVIDENCE/pytest.log" >&2
  exit "$status"
fi

if python3 -m tests.fence.verify_lab "$EVIDENCE" > "$EVIDENCE/verification.json"; then
  printf 'LAB_EVIDENCE_VERIFIED: %s\n' "$EVIDENCE/verification.json"
else
  status=$?
  printf 'LAB_GATE_FAILED: missing, partial, stale or untrusted witnesses\n' >&2
  exit "$status"
fi

# Deliberately NO attestation is auto-issued. A reviewer must inspect
# kernel witnesses and install a separately controlled root-owned attestation.
if (( REQUIRE_STRICT )); then
  printf 'STRICT_LAB_GATE_PASSED: independent deployment review still required\n'
fi
