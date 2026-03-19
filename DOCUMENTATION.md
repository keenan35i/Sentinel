# Mac Sentinel Documentation

This document explains the purpose of the project, how data flows through it, and what each major file is responsible for.

## 1. What the project is

Mac Sentinel is a **local-only macOS security triage application**.

It is designed for:
- broad host scanning for common macOS persistence and staging patterns
- conservative review of higher-signal host state such as TCC, profiles, trust settings, persistence, browser extensions, and code-signing provenance
- live local network-flow review
- offline import of local forensic artifacts such as STIX IOC files, Apple notifications, iPhone backups, and sysdiagnose folders

The project does **not** upload machine data, imported forensic artifacts, findings, or logs to any third-party service.

---

## 2. Main architecture

Mac Sentinel has three runtime layers.

### Python backend
The backend performs all sensitive work locally:
- host collection
- JSON rule evaluation
- structured host-intelligence checks
- local forensic artifact intake
- event and log storage
- API serving

### React frontend
The frontend is the review surface:
- scan controls
- live monitor controls
- diagnostics
- findings lists
- log views
- intelligence import workflow

### Electron shell
The Electron shell:
- launches the backend locally
- hosts the frontend as a desktop app
- exposes a very small local bridge for desktop actions
- blocks external navigation and desktop permission abuse

---

## 3. Data flow

### Full scan flow
1. UI requests `/api/scan/start`
2. backend starts `ScanService.run_full_scan()` in a worker thread
3. `RuntimeCollector` gathers low-level system data
4. `RuleEngine` evaluates JSON rules
5. `HostIntelligenceService` adds structured findings
6. `AppStateStore` stores status, findings, and logs
7. backend publishes revision changes
8. frontend refreshes only the panels whose revision changed

### Live monitor flow
1. UI toggles monitor on
2. `MonitorService` loops on a timer
3. `ScanService.collect_network_activity()` gathers current flows and network-only rule matches
4. connection snapshot and live findings are stored
5. bounded logs and event history are updated
6. revision stream notifies the renderer

### Local forensic import flow
1. UI opens a local file/directory picker through Electron preload
2. selected paths are sent to `/api/intelligence/import`
3. `LocalArtifactIntelligenceService` classifies and analyzes imported artifacts
4. imported artifacts, imported findings, and intelligence logs are stored locally
5. renderer updates the intelligence panels

---

## 4. Local storage model

Mac Sentinel uses two state styles.

### In-memory state
Used for:
- current scan status
- current monitor status
- current scan findings
- current monitor connection snapshot
- current imported intelligence snapshot

### Local SQLite ring buffer
Used for bounded long-lived state:
- scan logs
- monitor logs
- intelligence logs
- live monitor events
- snapshots and baselines

This avoids unbounded memory growth during long sessions.

Storage location is controlled by `src/mac_sentinel/config.py` and defaults to:
- `~/.mac_sentinel/mac_sentinel_local.db`

---

## 5. Root-level files

## `app.py`
Tiny bootstrap file. Starts the backend through `src.mac_sentinel.main.start()`.

## `README.md`
User-facing setup, usage, permissions, and testing guide.

## `DOCUMENTATION.md`
This architecture guide.

## `requirements.txt`
Python runtime dependencies.

## `requirements-dev.txt`
Python development and test dependencies.

## `package.json`
Electron/Vite/desktop build configuration and npm scripts.

## `package-lock.json`
Pinned npm dependency graph.

## `vite.config.js`
Vite build configuration for the React frontend.

## `install_local.sh`
Convenience installer for Python and Node dependencies in a local workflow.

## `launcher.command`
macOS-friendly launcher entry point intended for Finder/Desktop use.

## `run_app.sh`
Terminal-oriented run helper.

## `Dockerfile`
Container helper for controlled development/testing environments.

## `docker-compose.yml`
Companion compose file for container usage.

---

## 6. Data files

## `data/ioc_patterns.json`
Primary JSON ruleset.

This file is for rule-driven detections such as:
- suspicious launchd behavior
- suspicious process command lines
- suspicious network behaviors
- suspicious staged files
- conservative process indicators for profile install, trust install, and TCC abuse

Important design note:
- the JSON ruleset is **not** the only detection layer
- higher-value detections also come from `host_intelligence.py` and `forensics.py`

---

## 7. Python package root

## `src/mac_sentinel/__init__.py`
Package marker.

## `src/mac_sentinel/config.py`
Central configuration dataclass.

Controls:
- host and port
- monitor interval
- recursive enumeration limits
- retention limits
- local storage path
- SSE wait timing

This is the main place to tune performance and retention.

## `src/mac_sentinel/models.py`
Shared backend models.

Contains:
- `Finding` dataclass
- API request/response schemas
- diagnostics response models
- revision response model
- intelligence import models

This file defines the common shapes passed across routes and services.

## `src/mac_sentinel/main.py`
Backend composition root.

Responsibilities:
- instantiate storage
- instantiate collector/services
- wire everything together
- attach services to FastAPI app state
- build the router
- expose `start()` for uvicorn launch

---

## 8. API layer

## `src/mac_sentinel/api/__init__.py`
Package marker.

## `src/mac_sentinel/api/routes.py`
All FastAPI endpoints.

Groups:
- health
- revisions
- SSE revision stream
- scan control/status/findings/logs
- monitor control/status/events/connections/logs
- rule metadata/reload
- diagnostics
- intelligence summary/state/logs/import/clear
- path open and remediation actions

This file stays intentionally thin and delegates actual work to service classes.

---

## 9. Core backend services

## `src/mac_sentinel/core/__init__.py`
Package marker.

## `src/mac_sentinel/core/local_storage.py`
Local SQLite helper.

Responsibilities:
- create the local SQLite schema
- append bounded ring-buffer entries
- read recent logs/events
- store snapshots
- store baselines

This file is the foundation for long-session stability and local-only persistence.

## `src/mac_sentinel/core/state.py`
Thread-safe application state manager.

Responsibilities:
- hold current status objects in memory
- keep current findings and current monitor snapshot
- write logs/events into local ring storage
- maintain revision counters
- notify waiting revision-stream subscribers

This file is the central synchronization point between worker threads and API routes.

## `src/mac_sentinel/core/runtime.py`
Low-level OS-facing collector.

Responsibilities:
- process list collection via `ps`
- launchd label collection via `launchctl`
- network collection via `lsof`
- safe recursive file enumeration with timeouts and caps
- binary-aware text reads
- plist parsing
- installed configuration profile inventory
- TCC database reads
- diagnostic crash report discovery
- recent downloaded candidate discovery
- code-signing / quarantine / spctl metadata collection
- trust-settings inspection
- browser extension manifest inventory
- login item collection
- background item collection
- nested app-bundle component inspection

This file is the backend’s adapter to local macOS state.

## `src/mac_sentinel/core/content_filters.py`
False-positive control layer for content scanning.

Responsibilities:
- decide whether a file should be content scanned at all
- skip known binary/vendor/generated assets
- skip common packaged app resource paths
- skip scanner-owned/generated content such as rules and vendored assets

This file is one of the main reasons the scanner avoids obvious source-tree and vendor noise.

## `src/mac_sentinel/core/rules.py`
JSON rule repository and normalization layer.

Responsibilities:
- load `ioc_patterns.json`
- normalize missing optional fields
- expose metadata
- expose all rules
- expose network-only rules for live monitoring

## `src/mac_sentinel/core/scanner.py`
Rule engine and full scan coordinator.

Contains:

### `RuleEngine`
Evaluates a normalized JSON rule against:
- files and globs
- file paths
- file content
- plist labels/programs/arguments
- processes
- launchctl labels
- network connections

### `ScanService`
Runs full scans and live network snapshots.

Responsibilities:
- clear runtime caches
- sample a baseline
- evaluate rules one by one
- keep scanning after timeouts or rule-specific errors
- update scan progress and logs
- merge host-intelligence findings
- deduplicate and sort findings
- create live-monitor connection snapshots and live monitor findings

## `src/mac_sentinel/core/monitor.py`
Live monitor coordinator.

Responsibilities:
- periodically call `ScanService.collect_network_activity()`
- detect changes in connection snapshots
- append bounded observation logs
- deduplicate repeated live events for a cooldown window
- update monitor status

## `src/mac_sentinel/core/host_intelligence.py`
Structured host-intelligence layer.

This is where the cleaner, higher-signal checks live.

Responsibilities:
- installed profile review
- suspicious TCC grant review
- trust-settings context
- crash-burst context for Messages/IDS surface processes
- downloaded quarantined executable review
- browser extension risk review
- login item/background item persistence review
- app-bundle provenance and nested-component review
- local baseline diffing for profiles, TCC, trust, persistence, and risky browser extensions
- correlation findings across multiple signals

This file is designed to keep advanced detections more meaningful than raw keyword matching.

## `src/mac_sentinel/core/forensics.py`
Local forensic artifact intake.

Responsibilities:
- classify imported paths
- detect STIX IOC files
- load STIX literal indicators
- detect Apple threat-notification wording
- inspect backup/sysdiagnose-style directories
- search imported artifacts for IOC matches
- generate imported-intelligence findings and summaries
- update imported artifact state and intelligence logs

This file is the local forensic lane of the project.

## `src/mac_sentinel/core/diagnostics.py`
Diagnostics and permissions helper.

Responsibilities:
- report tool availability (`ps`, `launchctl`, `lsof`, `codesign`, `spctl`, `security`, `profiles`, etc.)
- report readability of protected macOS locations
- expose advanced host-intelligence summary into the diagnostics panel
- open Full Disk Access settings on macOS

## `src/mac_sentinel/core/remediation.py`
Human-triggered remediation helper.

Responsibilities:
- reveal paths in Finder
- stop attached processes when appropriate
- attempt launchctl removal for attached labels
- move files to Trash instead of hard deleting them
- avoid destructive action on protected system paths

This file is intentionally conservative.

---

## 10. Frontend files

## `frontend/index.html`
Vite renderer entry HTML.

## `frontend/src/main.jsx`
React entry point. Mounts the app.

## `frontend/src/api.js`
Frontend API helper.

Responsibilities:
- resolve backend base URL dynamically from Electron preload
- perform JSON API requests
- create the revision SSE stream

## `frontend/src/App.jsx`
Top-level renderer container.

Responsibilities:
- initial backend bootstrap calls
- revision-aware refresh logic
- SSE revision subscription with fallback polling
- toast handling
- artifact import flow
- orchestration of all major panels

## `frontend/src/styles/app.css`
Main renderer styling.

Responsibilities:
- layout
- cards/panels
- responsive behavior
- virtual list containment
- compact desktop visual design

### Frontend component files

## `frontend/src/components/HeaderBar.jsx`
Top hero/header block.

Shows:
- backend state
- rule count
- packaged/dev mode
- update transport state
- API endpoint

## `frontend/src/components/StatusPanel.jsx`
High-level status summary for scan/monitor/intelligence state.

## `frontend/src/components/ControlBar.jsx`
Scan and monitor controls.

Handles:
- start/pause/resume/stop scan
- toggle monitor
- reload rules
- open Full Disk Access settings

## `frontend/src/components/DiagnosticsPanel.jsx`
Diagnostics UI.

Shows command availability, readable paths, advanced host-intelligence summary, and recommendations.

## `frontend/src/components/FindingsPanel.jsx`
Reusable findings list panel.

Features:
- severity filter
- review-prompt copy
- open path action
- remediate action
- virtualized rendering

## `frontend/src/components/LogsPanel.jsx`
Reusable virtualized log panel.

## `frontend/src/components/TrafficPanel.jsx`
Live connection list panel.

Features:
- protocol filter
- loopback toggle
- stable per-row keys for live virtualization
- process/flow/service display

## `frontend/src/components/IntelligencePanel.jsx`
Imported-intelligence summary and artifact intake panel.

## `frontend/src/components/VirtualList.jsx`
Measured variable-height virtual list implementation.

Responsibilities:
- virtualize large result lists
- measure real row heights
- use stable per-item keys when supplied
- avoid overlap in dense result panels

---

## 11. Electron files

## `electron/main.cjs`
Electron desktop main process.

Responsibilities:
- launch the backend locally
- wait until the backend is healthy
- create the desktop window
- harden the Electron session
- deny permission requests
- block unexpected navigation
- expose limited IPC actions

## `electron/preload.cjs`
Very small secure bridge between renderer and main process.

Exposes only:
- backend URL
- app info request
- open-path action
- artifact chooser

No general Node access is exposed to the renderer.

---

## 12. Tests

## `tests/conftest.py`
Test path/bootstrap setup.

## `tests/test_api.py`
API-level tests.

## `tests/test_false_positive_controls.py`
Regression tests for false-positive suppression behavior.

## `tests/test_forensics_and_retention.py`
Tests for local forensic import and retention behavior.

## `tests/test_host_intelligence.py`
Tests for structured host-intelligence checks and diagnostics exposure.

## `tests/test_local_storage_and_extended_intelligence.py`
Tests for:
- local SQLite retention
- browser extension review
- persistence review
- provenance review
- revision wait behavior

## `tests/test_rule_noise_controls.py`
Tests for noisy-rule capping and directory noise controls.

## `tests/test_services.py`
Service integration tests for scanner and monitor behavior.

## `tests/test_ui_state_optimizations.py`
Backend-side revision optimization tests used by the UI refresh model.

---

## 13. Practical extension points

If you want to extend the project safely, the best entry points are:

### Add a new JSON detection
Edit:
- `data/ioc_patterns.json`

### Add a new structured host check
Edit:
- `src/mac_sentinel/core/host_intelligence.py`
- and, if needed, `src/mac_sentinel/core/runtime.py`

### Add a new imported artifact type
Edit:
- `src/mac_sentinel/core/forensics.py`

### Add a new UI panel
Edit:
- `frontend/src/App.jsx`
- `frontend/src/components/`
- `frontend/src/styles/app.css`

### Add a new desktop integration action
Edit:
- `electron/main.cjs`
- `electron/preload.cjs`

---

## 14. Design principles used in this codebase

1. **Local first**
   - no third-party upload path

2. **Prefer real state over keywords**
   - TCC entries, profiles, trust settings, code-signing, provenance, and imported forensics are stronger than generic string matches

3. **Correlation beats volume**
   - a few corroborated signals are more useful than a huge noisy ruleset

4. **Bound memory growth**
   - logs/events are trimmed in a local ring buffer

5. **Keep the UI responsive**
   - revision-based refresh
   - SSE updates
   - measured virtual lists

6. **Be conservative with destructive actions**
   - reveal or move to Trash
   - protect system paths

