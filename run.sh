#!/usr/bin/env bash
# Run Makrotik in the foreground (development / manual use).
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
if [ -x "$DIR/venv/bin/python" ]; then
    exec "$DIR/venv/bin/python" app.py
else
    exec python3 app.py
fi
