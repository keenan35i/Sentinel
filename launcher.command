#!/bin/bash
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

if [ ! -d ".venv" ]; then
  /usr/bin/env python3 -m venv .venv
fi

source .venv/bin/activate
python -m pip install --upgrade pip >/dev/null
python -m pip install -r requirements.txt -r requirements-dev.txt >/dev/null

if [ ! -d "node_modules" ]; then
  npm install >/dev/null
fi

NEEDS_BUILD=0
if [ ! -f "dist/renderer/index.html" ]; then
  NEEDS_BUILD=1
else
  if find frontend electron vite.config.js package.json -type f -newer dist/renderer/index.html | grep -q .; then
    NEEDS_BUILD=1
  fi
fi

if [ "$NEEDS_BUILD" -eq 1 ]; then
  npm run build >/dev/null
fi

exec npx electron .
