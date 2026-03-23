# Active Protection (local-only)

This patch adds an **Active Protection** layer to Mac Sentinel with an on/off toggle in the UI and API.

## What it does

While enabled, the backend runs a bounded local-only protection loop that watches for:

- newly launched suspicious processes
- newly created or modified suspicious files in common drop zones
- suspicious `LaunchAgents` / `LaunchDaemons` persistence items
- suspicious outbound network behavior
- high-confidence rule-based live findings from the existing monitor stack

## Response model

When a finding is **high-confidence** and Active Protection is in `protect` mode, the app can:

- terminate the matching PID
- attempt `launchctl remove` for a matching label
- move the file to a **local quarantine directory** under the app's state folder

No telemetry is uploaded. State, logs, events, and quarantine remain local to the machine.

## Design notes

This implementation intentionally follows the broad pattern used by mainstream security suites:

- always-on / real-time layer
- behavior monitoring instead of only static signatures
- persistence and startup monitoring
- bounded automatic response for higher-confidence detections
- local event history and operator-visible protection status

## Important limits

This is still **not** a full Apple EndpointSecurity or NetworkExtension product.

Current implementation uses local polling and bounded snapshots while the app is running. It does **not** provide:

- Apple EndpointSecurity event subscriptions
- system-wide network content filtering / blocking
- kernel telemetry
- exploit prevention hooks at the OS provider level
- tamper-resistant agent protections comparable to enterprise EDR products

Those capabilities would require separately signed Apple system extensions with the necessary entitlements.

## API

- `GET /api/protection/status`
- `POST /api/protection/enable`
- `POST /api/protection/disable`
- `GET /api/protection/events`
- `GET /api/protection/logs`

## UI

The React UI now shows:

- Active Protection toggle
- Active Protection status pills
- Active Protection events panel
- Active Protection logs panel
