#!/bin/bash
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

/usr/bin/env python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt -r requirements-dev.txt
npm install
npm run build

echo "Dependencies installed and renderer built."
echo "Run ./launcher.command to start the Electron desktop app."
echo "The launcher will automatically rebuild the renderer if frontend files changed."
echo "Run npm run dist:mac on a Mac to package a standalone macOS build."
