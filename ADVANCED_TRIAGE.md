# Advanced Triage Additions

This update pushes Mac Sentinel beyond simple keyword rules and recurring `lsof` snapshots by adding higher-fidelity **offline triage and correlation** for modern macOS investigations.

## What was added

### 1) EndpointSecurity export ingestion
Mac Sentinel can now ingest local **Endpoint Security JSONL / NDJSON exports** and flag:
- execution from untrusted locations such as Downloads, temp paths, and transient folders
- access to persistence-sensitive paths such as LaunchAgents, LaunchDaemons, TCC databases, configuration-profile storage, and privileged helper locations
- suspicious image mappings from unusual paths
- reconstructed chains such as **exec -> sensitive write** and **exec -> suspicious image mapping**

### 2) Host unified log triage
A new API route collects local `log show --style json` output and correlates:
- Messages / IDS / WebContent attack-surface context
- TCC / privacy-control activity
- configuration profile activity
- combined multi-signal chains inside a single triage window

### 3) Memory-artifact parsing
Mac Sentinel now parses imported text artifacts such as:
- `vmmap` exports
- `sample` outputs
- `spindump` outputs
- `leaks` outputs

It looks for:
- suspicious memory / injection API markers
- writable-and-executable memory references
- unusual dylib / image paths from temp or download-like locations

### 4) Crash / ips correlation
Imported `.crash` and `.ips` files are now parsed for attack-surface processes such as:
- `MessagesBlastDoorService`
- `imagent`
- `identityservicesd`
- `WebContent`

The service can also use the local runtime collector to index recent diagnostic reports and turn bursts into triage findings.

### 5) Stronger cross-artifact correlation
The correlation layer now raises priority when it sees combinations like:
- Apple threat notification + STIX match
- sysdiagnose context + STIX match
- EndpointSecurity chain + memory-artifact signal
- unified log context + EndpointSecurity chain

## New API route

### Collect local host triage
`POST /api/intelligence/collect-host-triage`

Example body:
```json
{
  "last_minutes": 90
}
```

This collects a bounded local triage snapshot from unified logs and recent diagnostic-report indexes, stores the result in the existing intelligence state, and returns findings in the same format as `/api/intelligence/import`.

## Important platform reality

This update **does not magically grant direct kernel-level or entitlement-protected telemetry** to the Python / Electron app.

For real-time high-fidelity macOS telemetry, you still need a **separately built, signed, and Apple-entitled EndpointSecurity system extension / client** that exports events locally for Mac Sentinel to ingest.

That is the realistic architecture on current macOS:
- **Swift / system extension / entitled client** for raw ES telemetry collection
- **Python Mac Sentinel** for local storage, offline parsing, scoring, correlation, and UI presentation

## Suggested next phase

Build a small Swift collector that:
- subscribes to the exact ES event families you need
- writes bounded local JSONL files or a local socket stream
- includes signing / team / cdhash metadata where available
- rotates exports into the Mac Sentinel state directory for ingestion

That keeps collection realistic on modern macOS while letting the existing app stay useful as the analysis and triage layer.
