#!/usr/bin/env bash
set -euo pipefail

ROLE="${ROLE:-}"

# Get container IP (docker guarantees uniqueness per container)
IP_LAST_OCTET="$(hostname -i | awk '{print $1}' | awk -F'.' '{print $NF}')"

# Optional: keep IDs small & predictable
IDX="$((IP_LAST_OCTET % 100))"
IDX="${IDX:-1}"

UTILITY_ID_OFFSET="${UTILITY_ID_OFFSET:-1}"
BASE_METER_ID_OFFSET="${BASE_METER_ID_OFFSET:-1}"

export CA_HOST="${CA_HOST:-ca}"
export CA_PORT="${CA_PORT:-5005}"

if [[ "$ROLE" == "ca" ]]; then
  exec python -u cert_auth.py
elif [[ "$ROLE" == "utility" ]]; then
  export UTILITY_ID="$((UTILITY_ID_OFFSET + IDX - 1))"
  echo "[ENTRYPOINT] Utility ID = $UTILITY_ID"
  exec python -u utility.py
elif [[ "$ROLE" == "base_meter" ]]; then
  export BASE_METER_ID="$((BASE_METER_ID_OFFSET + IDX - 1))"
  echo "[ENTRYPOINT] Base Meter ID = $BASE_METER_ID"
  exec python -u base_meter.py
else
  echo "ROLE must be one of: ca | utility | base_meter"
  exit 1
fi
