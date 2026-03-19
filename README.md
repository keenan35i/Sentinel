# Mac Sentinel

Mac Sentinel is a **local-first macOS security triage desktop app**.

It combines:
- a **Python backend** for host collection, rule evaluation, structured host-intelligence checks, local artifact intake, and local state storage
- a **React frontend** for reviewing scans, live traffic, diagnostics, logs, imported forensic artifacts, and correlation findings
- an **Electron shell** so the app runs as a standalone desktop application instead of a browser tab

## Local-only design

Mac Sentinel does **not** upload:
- host telemetry
- findings
- logs
- imported iPhone backups
- sysdiagnose folders
- STIX files
- Apple threat-notification artifacts

All analysis is performed locally on the machine running the app.

## What it detects

### Rule-driven detection
The JSON ruleset in `data/ioc_patterns.json` covers:
- suspicious launch items
- staged droppers and common drop locations
- suspicious process command lines
- suspicious network patterns
- conservative process indicators for profile install, trust install, and TCC abuse

### Structured host-intelligence detection
The backend also evaluates stronger host-state signals such as:
- installed sensitive configuration profiles
- suspicious TCC grants from real `TCC.db` state
- trust-store changes
- suspicious login items and background items
- high-risk browser extension capability combinations
- downloaded quarantined executables and app bundles with weak provenance
- unsigned nested helpers inside downloaded app bundles
- diagnostic crash context for Messages / IDS attack-surface processes
- local baseline diffs for sensitive host state
- correlation findings across multiple signals

### Offline forensic import
You can import local artifacts such as:
- Apple threat notifications
- STIX IOC files
- iPhone/iPad backup folders
- sysdiagnose folders
- other local directories and files for offline review

## Main behavior improvements in this version

This revision adds:
- **dynamic backend URL handling** in the renderer
- **Electron hardening** with sandboxing, blocked permission prompts, and navigation restrictions
- **server-sent revision updates** instead of relying on aggressive polling
- **stable virtual-list keys** for live traffic rows
- **local SQLite ring-buffer storage** for logs/events so memory stays bounded during long sessions
- **baseline diffing** for profiles, TCC, trust settings, persistence, and high-risk browser extensions
- **expanded provenance checks** using quarantine, `codesign`, `spctl`, notarization, origin URLs, and nested bundle component review
- **broader persistence and extension review** for login items, background items, and browser manifests
- **more tests** covering local storage, persistence, browser extension review, provenance review, and revision waiting

## Installation

### Option A: local workflow

```bash
./install_local.sh
./launcher.command
```

### Option B: backend only

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
python app.py
```

The backend listens on:

```text
http://127.0.0.1:8765
```

### Option C: Electron dev workflow

```bash
npm install
npm run backend:install
npm run dev
```

### Option D: packaged macOS build

```bash
npm install
npm run dist:mac
```

## Permissions and visibility

Mac Sentinel cannot silently grant itself Full Disk Access.

For best visibility:
- give **Full Disk Access** to the packaged Mac Sentinel app bundle when using the desktop build
- during development, give access to the terminal app you are launching from only if needed
- use the Diagnostics panel to confirm what protected areas are readable

Without Full Disk Access, macOS may block access to:
- Mail
- Messages
- Safari
- TCC databases
- some launch and profile-related locations

## Running tests

```bash
pytest -q
```

Current test coverage includes:
- API behavior
- false-positive controls
- rule-noise controls
- host-intelligence logic
- forensic import behavior
- local ring-buffer storage behavior
- persistence and browser extension review
- provenance review
- revision/update optimization behavior

## Project map

Important files:

```text
app.py                                  Backend entry point
src/mac_sentinel/main.py                FastAPI app factory and service wiring
src/mac_sentinel/api/routes.py          API routes and SSE stream
src/mac_sentinel/core/runtime.py        Low-level macOS collectors
src/mac_sentinel/core/scanner.py        JSON rule engine and scan orchestration
src/mac_sentinel/core/host_intelligence.py  Structured host-intelligence checks
src/mac_sentinel/core/forensics.py      Offline local artifact intake
src/mac_sentinel/core/local_storage.py  Local SQLite ring buffer and baseline storage
src/mac_sentinel/core/state.py          Thread-safe app state and revisions
frontend/src/                           React renderer
electron/                               Electron desktop shell
tests/                                  Backend tests
data/ioc_patterns.json                  Rule-driven detections
```

## More detail

For a full per-file breakdown, see:

```text
DOCUMENTATION.md
```
