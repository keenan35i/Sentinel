from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


@dataclass
class Finding:
    rule_id: str
    title: str
    family: str
    threat_level: str
    author_or_actor: str
    description: str
    evidence_type: str
    source: str = "scan"
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    matched_path: str = ""
    matched_pid: Optional[int] = None
    process_name: str = ""
    process_cmdline: str = ""
    launchd_label: str = ""
    local_address: str = ""
    local_port: Optional[int] = None
    remote_address: str = ""
    remote_port: Optional[int] = None
    protocol: str = ""
    matched_regex: str = ""
    confidence: str = "context"
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))

    def to_dict(self) -> Dict:
        return asdict(self)


class ActionRequest(BaseModel):
    source: str = Field(default="scan", pattern="^(scan|live|intel|protect)$")
    finding_id: str


class ActionResult(BaseModel):
    ok: bool
    actions: List[str]


class ImportArtifactsRequest(BaseModel):
    paths: List[str] = Field(default_factory=list)




class CollectHostTriageRequest(BaseModel):
    last_minutes: int = Field(default=90, ge=5, le=1440)


class ImportArtifactsResponse(BaseModel):
    ok: bool
    imported_count: int
    finding_count: int
    artifacts: List[Dict]
    findings: List[Dict]
    notes: List[str] = Field(default_factory=list)


class IntelligenceStateResponse(BaseModel):
    artifacts: List[Dict]
    findings: List[Dict]
    summary: Dict = Field(default_factory=dict)


class ScanStatusResponse(BaseModel):
    running: bool
    paused: bool = False
    stop_requested: bool = False
    cancelled: bool = False
    last_started: Optional[str] = None
    last_finished: Optional[str] = None
    count: int = 0
    error: str = ""
    total_rules: int = 0
    scanned_rules: int = 0
    current_rule: str = ""
    progress_percent: int = 0


class MonitorStatusResponse(BaseModel):
    running: bool
    last_started: Optional[str] = None
    event_count: int = 0
    last_cycle: Optional[str] = None
    observed_connection_count: int = 0
    error: str = ""




class ProtectionStatusResponse(BaseModel):
    enabled: bool
    running: bool
    mode: str = 'protect'
    last_started: Optional[str] = None
    last_cycle: Optional[str] = None
    event_count: int = 0
    blocked_count: int = 0
    quarantined_count: int = 0
    watched_path_count: int = 0
    local_only: bool = True
    error: str = ''


class RuleMetadataResponse(BaseModel):
    schema_version: int
    rule_count: int
    about: str = ""


class FindingsResponse(BaseModel):
    findings: List[Dict]


class LogsResponse(BaseModel):
    logs: List[Dict]


class ConnectionsResponse(BaseModel):
    connections: List[Dict]


class RevisionsResponse(BaseModel):
    scan_status: int
    scan_findings: int
    scan_logs: int
    monitor_status: int
    monitor_events: int
    monitor_logs: int
    monitor_connections: int
    intelligence_findings: int
    intelligence_artifacts: int
    intelligence_logs: int
    intelligence_summary: int
    protection_status: int
    protection_events: int
    protection_logs: int


class DiagnosticsResponse(BaseModel):
    app_name: str
    platform: str
    is_macos: bool
    python_executable: str
    python_version: str
    commands: Dict[str, Dict]
    permission_checks: List[Dict]
    recommendations: List[str]
    notes: List[str]
    advanced_checks: Dict = Field(default_factory=dict)
