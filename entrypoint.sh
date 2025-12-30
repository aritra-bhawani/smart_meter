#!/usr/bin/env bash
set -euo pipefail

ROLE="${ROLE:-}"

export CA_HOST="${CA_HOST:-ca}"
export CA_PORT="${CA_PORT:-5005}"

if [[ "$ROLE" == "ca" ]]; then
  exec python -u cert_auth.py
elif [[ "$ROLE" == "utility" ]]; then
  exec python -u utility.py
elif [[ "$ROLE" == "base_meter" ]]; then
  exec python -u base_meter.py
else
  echo "ROLE must be one of: ca | utility | base_meter"
  exit 1
fi