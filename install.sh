#!/usr/bin/env bash
# One-shot installer for Makrotik Share on Ubuntu/Debian.
# Usage:
#   git clone <repo-url>
#   cd <repo>
#   sudo bash install.sh
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root: sudo bash install.sh"
    exit 1
fi
cd "$(dirname "$0")"
python3 setup.py
