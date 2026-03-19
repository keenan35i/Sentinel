from __future__ import annotations

import json
import threading
import time
from typing import Dict

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from ..models import (
    ActionRequest,
    ActionResult,
    ConnectionsResponse,
    DiagnosticsResponse,
    FindingsResponse,
    ImportArtifactsRequest,
    ImportArtifactsResponse,
    IntelligenceStateResponse,
    LogsResponse,
    MonitorStatusResponse,
    RevisionsResponse,
    RuleMetadataResponse,
    ScanStatusResponse,
)


def build_router(app_services: Dict) -> APIRouter:
    router = APIRouter()

    rules = app_services['rules']
    state = app_services['state']
    scanner = app_services['scanner']
    monitor = app_services['monitor']
    remediation = app_services['remediation']
    diagnostics = app_services['diagnostics']
    intelligence = app_services.get('intelligence')
    forensics = app_services.get('forensics')

    @router.get('/health')
    def health():
        return {'ok': True, 'service': 'mac-sentinel'}

    @router.get('/revisions', response_model=RevisionsResponse)
    def revisions():
        return RevisionsResponse(**state.revisions())

    @router.get('/events/stream')
    def events_stream():
        def iterator():
            previous = None
            while True:
                revisions = state.wait_for_revision_change(previous=previous, timeout=20)
                payload = {
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'revisions': revisions,
                }
                previous = revisions
                yield f"event: revisions\ndata: {json.dumps(payload)}\n\n"
        return StreamingResponse(iterator(), media_type='text/event-stream', headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
        })

    @router.post('/scan/start', response_model=ScanStatusResponse)
    def start_scan():
        status = state.scan_status()
        if status['running']:
            return ScanStatusResponse(**status)

        total_rules = len(rules.all_rules())
        state.begin_scan(total_rules=total_rules)

        def worker():
            try:
                scanner.run_full_scan()
            except Exception as exc:
                state.fail_scan(str(exc))

        threading.Thread(target=worker, name='mac-sentinel-scan', daemon=True).start()
        return ScanStatusResponse(**state.scan_status())

    @router.post('/scan/pause', response_model=ScanStatusResponse)
    def pause_scan():
        state.pause_scan()
        return ScanStatusResponse(**state.scan_status())

    @router.post('/scan/resume', response_model=ScanStatusResponse)
    def resume_scan():
        state.resume_scan()
        return ScanStatusResponse(**state.scan_status())

    @router.post('/scan/stop', response_model=ScanStatusResponse)
    def stop_scan():
        state.request_stop_scan()
        return ScanStatusResponse(**state.scan_status())

    @router.get('/scan/status', response_model=ScanStatusResponse)
    def scan_status():
        return ScanStatusResponse(**state.scan_status())

    @router.get('/scan/findings', response_model=FindingsResponse)
    def scan_findings():
        return FindingsResponse(findings=state.scan_findings())

    @router.get('/scan/logs', response_model=LogsResponse)
    def scan_logs():
        return LogsResponse(logs=state.scan_logs())

    @router.post('/monitor/start', response_model=MonitorStatusResponse)
    def monitor_start():
        monitor.start()
        return MonitorStatusResponse(**state.monitor_status())

    @router.post('/monitor/stop', response_model=MonitorStatusResponse)
    def monitor_stop():
        monitor.stop()
        return MonitorStatusResponse(**state.monitor_status())

    @router.get('/monitor/status', response_model=MonitorStatusResponse)
    def monitor_status():
        return MonitorStatusResponse(**state.monitor_status())

    @router.get('/monitor/events', response_model=FindingsResponse)
    def monitor_events():
        return FindingsResponse(findings=state.live_events())

    @router.get('/monitor/connections', response_model=ConnectionsResponse)
    def monitor_connections():
        return ConnectionsResponse(connections=state.monitor_connections())

    @router.delete('/monitor/events', response_model=ActionResult)
    def clear_monitor_events():
        state.clear_live_events()
        return ActionResult(ok=True, actions=['Cleared live monitor events'])

    @router.get('/monitor/logs', response_model=LogsResponse)
    def monitor_logs():
        return LogsResponse(logs=state.monitor_logs())

    @router.get('/rules/metadata', response_model=RuleMetadataResponse)
    def rule_metadata():
        return RuleMetadataResponse(**rules.metadata())

    @router.get('/rules')
    def all_rules():
        return {'rules': rules.all_rules()}

    @router.post('/rules/reload', response_model=RuleMetadataResponse)
    def reload_rules():
        rules.reload()
        return RuleMetadataResponse(**rules.metadata())

    @router.get('/diagnostics', response_model=DiagnosticsResponse)
    def get_diagnostics():
        return DiagnosticsResponse(**diagnostics.get_report())

    @router.get('/intelligence/summary')
    def intelligence_summary():
        return intelligence.diagnostics_summary() if intelligence else {}

    @router.get('/intelligence/state', response_model=IntelligenceStateResponse)
    def intelligence_state():
        return IntelligenceStateResponse(
            artifacts=state.intelligence_artifacts(),
            findings=state.intelligence_findings(),
            summary=state.intelligence_summary(),
        )

    @router.get('/intelligence/logs', response_model=LogsResponse)
    def intelligence_logs():
        return LogsResponse(logs=state.intelligence_logs())

    @router.post('/intelligence/import', response_model=ImportArtifactsResponse)
    def import_intelligence(payload: ImportArtifactsRequest):
        if not forensics:
            raise HTTPException(status_code=503, detail='Local forensic intake service is not available.')
        result = forensics.import_paths(payload.paths)
        return ImportArtifactsResponse(**result)

    @router.delete('/intelligence/state', response_model=ActionResult)
    def clear_intelligence_state():
        if forensics:
            forensics.clear()
        else:
            state.clear_intelligence()
        return ActionResult(ok=True, actions=['Cleared imported intelligence artifacts and findings'])

    @router.post('/permissions/open-full-disk-access', response_model=ActionResult)
    def open_full_disk_access():
        actions = diagnostics.open_full_disk_access_settings()
        return ActionResult(ok=True, actions=actions)

    @router.post('/finding/open', response_model=ActionResult)
    def open_finding(payload: ActionRequest):
        finding = state.get_finding(payload.source, payload.finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail='Finding not found.')
        actions = remediation.open_related_location(finding)
        return ActionResult(ok=True, actions=actions)

    @router.post('/finding/remediate', response_model=ActionResult)
    def remediate_finding(payload: ActionRequest):
        finding = state.get_finding(payload.source, payload.finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail='Finding not found.')
        actions = remediation.remediate(finding)
        return ActionResult(ok=True, actions=actions)

    return router
