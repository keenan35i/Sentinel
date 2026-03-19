#!/bin/bash
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
mkdir -p "$HOME/Library/Logs/Mac Sentinel"
LOGFILE="$HOME/Library/Logs/Mac Sentinel/bootstrap.log"

if [ ! -d ".venv" ]; then
  /usr/bin/env python3 -m venv .venv >>"$LOGFILE" 2>&1
fi
source .venv/bin/activate
python -m pip install --upgrade pip >>"$LOGFILE" 2>&1
python -m pip install -r requirements.txt >>"$LOGFILE" 2>&1
( sleep 2 && open "http://127.0.0.1:8765/ui/index.html" ) >/dev/null 2>&1 &
exec python app.py >>"$LOGFILE" 2>&1
