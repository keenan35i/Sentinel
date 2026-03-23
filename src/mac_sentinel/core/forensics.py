from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Set, Tuple

from ..models import Finding

TEXT_EXTENSIONS = {
    '.txt', '.log', '.json', '.jsonl', '.ndjson', '.stix2', '.xml', '.plist', '.md', '.html', '.htm', '.eml',
    '.ips', '.crash', '.conf', '.cfg', '.yaml', '.yml', '.sql', '.csv', '.tsv', '.js', '.py'
}

BACKUP_MARKERS = {'Manifest.db', 'Info.plist', 'Status.plist'}
SYSDIAG_MARKERS = {'Shutdown.log'}
APPLE_NOTIFICATION_PATTERNS = (
    re.compile(r'apple\s+threat\s+notification', re.I),
    re.compile(r'mercenary\s+spyware', re.I),
    re.compile(r'targeted\s+by\s+mercenary\s+spyware', re.I),
)

SYSDIAG_CONTEXT_PATTERNS = (
    re.compile(r'MessagesBlastDoorService', re.I),
    re.compile(r'imagent', re.I),
    re.compile(r'identityservicesd', re.I),
)

STIX_LITERAL_PATTERN = re.compile(r"'([^']{3,200})'")
ENDPOINT_EVENT_CANDIDATES = {
    'AUTH_EXEC', 'NOTIFY_EXEC', 'AUTH_OPEN', 'NOTIFY_OPEN', 'AUTH_CREATE', 'NOTIFY_CREATE', 'AUTH_WRITE',
    'NOTIFY_WRITE', 'AUTH_RENAME', 'NOTIFY_RENAME', 'AUTH_UNLINK', 'NOTIFY_UNLINK', 'AUTH_MMAP', 'NOTIFY_MMAP'
}
SUSPICIOUS_PERSISTENCE_PATHS = (
    '/Library/LaunchAgents/',
    '/Library/LaunchDaemons/',
    '/Users/',
    '/Library/PrivilegedHelperTools/',
    '/System/Volumes/Data/private/var/db/ConfigurationProfiles/',
    '/Library/Application Support/com.apple.TCC/TCC.db',
)
SUSPICIOUS_USER_PERSISTENCE_SUFFIXES = (
    '/Library/LaunchAgents',
    '/Library/LaunchDaemons',
    '/Library/Application Support/com.apple.backgroundtaskmanagementagent',
)
SUSPICIOUS_MEMORY_MARKERS = (
    re.compile(r'DYLD_INSERT_LIBRARIES', re.I),
    re.compile(r'frida', re.I),
    re.compile(r'cycript', re.I),
    re.compile(r'task_for_pid', re.I),
    re.compile(r'mach_vm_read', re.I),
    re.compile(r'vm_read', re.I),
    re.compile(r'ptrace', re.I),
    re.compile(r'jailbreak', re.I),
)
SUSPICIOUS_IMAGE_PATH = re.compile(
    r'(/private/var/folders/|/tmp/|/var/tmp/|/Users/[^\s]+/Downloads/|/Users/[^\s]+/Library/Containers/)',
    re.I,
)
UNIFIED_LOG_SUSPICIOUS_PATTERNS = (
    ('messages_attack_surface_crash', re.compile(r'(MessagesBlastDoorService|imagent|identityservicesd|WebContent)', re.I)),
    ('tcc_change', re.compile(r'\bTCC\b|kTCCService|tccd', re.I)),
    ('profile_change', re.compile(r'ConfigurationProfiles|profile install|profile remove|mdmclient', re.I)),
    ('gatekeeper_bypass_context', re.compile(r'syspolicyd|Gatekeeper|spctl', re.I)),
)


@dataclass
class StixIndicatorSet:
    source_path: str
    name: str
    literals: List[str]
    raw_indicator_count: int


class LocalArtifactIntelligenceService:
    """Analyze user-selected local artifacts without sending data off-machine.

    This service is intentionally local-first and can ingest richer telemetry artifacts,
    including unified log exports, Endpoint Security JSONL exports, crash / spindump / sample
    style reports, and memory-analysis text exports. Direct EndpointSecurity collection still
    requires a separately signed and entitled macOS system extension; this service focuses on
    offline analysis and correlation once the data is available locally.
    """

    def __init__(self, state_store, collector=None):
        self.state_store = state_store
        self.collector = collector
        self._stix_sets: List[StixIndicatorSet] = []

    def import_paths(self, paths: Sequence[str]) -> Dict:
        cleaned = [os.path.expanduser(path) for path in paths if path]
        findings: List[Finding] = []
        artifacts: List[Dict] = []
        notes: List[str] = []

        self.state_store.append_intelligence_log(f'Starting local artifact intake for {len(cleaned)} path(s).', phase='start')

        for raw_path in cleaned:
            path = Path(raw_path)
            if not path.exists():
                self.state_store.append_intelligence_log(f'Skipped missing artifact path: {raw_path}', level='warning', phase='skip')
                continue

            kind = self._detect_kind(path)
            artifact = {
                'path': str(path),
                'kind': kind,
                'name': path.name or str(path),
                'size_bytes': path.stat().st_size if path.is_file() else 0,
            }
            artifacts.append(artifact)
            self.state_store.append_intelligence_log(f'Analyzing {kind} artifact: {path}', phase='analyze')

            if kind == 'stix':
                stix_set = self._load_stix_file(path)
                if stix_set:
                    self._stix_sets.append(stix_set)
                    notes.append(f'Loaded {stix_set.raw_indicator_count} STIX indicator(s) from {path.name}.')
                    self.state_store.append_intelligence_log(
                        f'Loaded {stix_set.raw_indicator_count} STIX indicator(s) from {path.name}.',
                        phase='stix',
                    )
                continue

            findings.extend(self._analyze_path(path, kind))

        findings.extend(self._correlate_intel_findings(findings))
        deduped = self._dedupe_findings(findings)
        summary = self.summary(artifacts=artifacts, findings=deduped)
        self.state_store.set_intelligence_snapshot(artifacts, [item.to_dict() for item in deduped], summary)
        return {
            'ok': True,
            'imported_count': len(artifacts),
            'finding_count': len(deduped),
            'artifacts': artifacts,
            'findings': [item.to_dict() for item in deduped],
            'notes': notes,
        }

    def collect_host_triage(self, last_minutes: int = 90) -> Dict:
        if not self.collector:
            return {
                'ok': False,
                'imported_count': 0,
                'finding_count': 0,
                'artifacts': [],
                'findings': [],
                'notes': ['Runtime collector is not available for host triage collection.'],
            }

        minutes = max(5, min(int(last_minutes or 90), 24 * 60))
        self.state_store.append_intelligence_log(
            f'Collecting local host triage artifacts for the last {minutes} minute(s).', phase='collect'
        )

        findings: List[Finding] = []
        artifacts: List[Dict] = []
        notes: List[str] = []

        try:
            log_entries = self.collector.collect_unified_logs_json(last_minutes=minutes)
        except Exception as exc:
            log_entries = []
            notes.append(f'Unified log collection failed: {exc}')
            self.state_store.append_intelligence_log(f'Unified log collection failed: {exc}', level='warning', phase='collect')

        artifacts.append({
            'path': '',
            'kind': 'host-unified-log',
            'name': f'Unified logs ({minutes}m)',
            'size_bytes': len(log_entries),
            'entry_count': len(log_entries),
        })
        findings.extend(self._unified_log_findings_from_entries(log_entries, source_label='host-unified-log'))

        try:
            reports = self.collector.collect_diagnostic_reports(days=7, limit=120)
        except Exception:
            reports = []
        if reports:
            artifacts.append({
                'path': '',
                'kind': 'host-diagnostic-report-index',
                'name': 'Recent diagnostic reports',
                'size_bytes': len(reports),
                'entry_count': len(reports),
            })
            findings.extend(self._diagnostic_index_findings(reports))

        findings.extend(self._correlate_intel_findings(findings))
        deduped = self._dedupe_findings(findings)
        summary = self.summary(artifacts=artifacts, findings=deduped)
        self.state_store.set_intelligence_snapshot(artifacts, [item.to_dict() for item in deduped], summary)
        return {
            'ok': True,
            'imported_count': len(artifacts),
            'finding_count': len(deduped),
            'artifacts': artifacts,
            'findings': [item.to_dict() for item in deduped],
            'notes': notes,
        }

    def summary(self, artifacts: Sequence[Dict] | None = None, findings: Sequence[Finding] | None = None) -> Dict:
        artifacts = list(artifacts) if artifacts is not None else self.state_store.intelligence_artifacts()
        findings_payload = [item.to_dict() if isinstance(item, Finding) else dict(item) for item in (findings if findings is not None else self.state_store.intelligence_findings())]
        by_kind: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        for item in artifacts:
            by_kind[item.get('kind', 'unknown')] = by_kind.get(item.get('kind', 'unknown'), 0) + 1
        for item in findings_payload:
            by_severity[item.get('threat_level', 'unknown')] = by_severity.get(item.get('threat_level', 'unknown'), 0) + 1
        return {
            'artifact_count': len(artifacts),
            'finding_count': len(findings_payload),
            'artifacts_by_kind': by_kind,
            'findings_by_severity': by_severity,
            'loaded_stix_sets': len(self._stix_sets),
            'local_only': True,
        }

    def clear(self) -> None:
        self._stix_sets = []
        self.state_store.clear_intelligence()

    def _analyze_path(self, path: Path, kind: str) -> List[Finding]:
        findings: List[Finding] = []
        if path.is_file():
            findings.extend(self._apple_notification_findings(path))
            findings.extend(self._stix_match_findings(path, root_label=kind))
            if path.name == 'Shutdown.log':
                findings.extend(self._sysdiagnose_shutdown_findings(path))
            if kind == 'endpointsecurity-jsonl':
                findings.extend(self._endpointsecurity_findings(path))
            elif kind == 'unified-log-json':
                findings.extend(self._unified_log_findings_from_file(path))
            elif kind in {'vmmap-report', 'sample-report', 'spindump-report', 'leaks-report'}:
                findings.extend(self._memory_artifact_findings(path, kind))
            elif kind in {'crash-report', 'ips-report'}:
                findings.extend(self._crash_report_findings(path))
            return findings

        if kind == 'backup':
            findings.extend(self._backup_presence_findings(path))
        if kind == 'sysdiagnose':
            findings.extend(self._sysdiagnose_dir_findings(path))

        findings.extend(self._directory_stix_match_findings(path, kind))
        return findings

    def _detect_kind(self, path: Path) -> str:
        name_lower = path.name.lower()
        suffix = path.suffix.lower()
        if path.is_file() and suffix in {'.stix2', '.stix', '.json'}:
            try:
                payload = json.loads(path.read_text(encoding='utf-8', errors='ignore'))
            except Exception:
                payload = None
            if isinstance(payload, dict) and payload.get('type') == 'bundle':
                return 'stix'
        if path.is_file() and (suffix in {'.jsonl', '.ndjson'} or 'endpointsecurity' in name_lower or name_lower.startswith('es_')):
            return 'endpointsecurity-jsonl'
        if path.is_file() and (name_lower.startswith('vmmap') or 'vmmap' in name_lower):
            return 'vmmap-report'
        if path.is_file() and ('spindump' in name_lower):
            return 'spindump-report'
        if path.is_file() and (name_lower.startswith('sample') or 'sample_' in name_lower):
            return 'sample-report'
        if path.is_file() and ('leaks' in name_lower):
            return 'leaks-report'
        if path.is_file() and suffix == '.ips':
            return 'ips-report'
        if path.is_file() and suffix == '.crash':
            return 'crash-report'
        if path.is_file() and suffix in {'.json', '.log'}:
            text = self._safe_read_text(path, max_bytes=512 * 1024)
            if 'traceID' in text or 'subsystem' in text or 'eventMessage' in text or 'composedMessage' in text:
                return 'unified-log-json'
        if path.is_file() and path.suffix.lower() in {'.txt', '.html', '.htm', '.eml'}:
            text = self._safe_read_text(path)
            if self._looks_like_apple_notification(text):
                return 'apple-notification'
        if path.is_dir():
            entries = {child.name for child in path.iterdir()} if path.exists() else set()
            if BACKUP_MARKERS.issubset(entries):
                return 'backup'
            if self._directory_contains(path, SYSDIAG_MARKERS):
                return 'sysdiagnose'
            return 'directory'
        if path.name == 'Shutdown.log':
            return 'sysdiagnose-log'
        return 'file'

    def _load_stix_file(self, path: Path) -> StixIndicatorSet | None:
        try:
            payload = json.loads(path.read_text(encoding='utf-8', errors='ignore'))
        except Exception:
            return None
        objects = payload.get('objects', []) if isinstance(payload, dict) else []
        literals: Set[str] = set()
        indicator_count = 0
        for obj in objects:
            if not isinstance(obj, dict) or obj.get('type') != 'indicator':
                continue
            indicator_count += 1
            pattern = str(obj.get('pattern', ''))
            for literal in STIX_LITERAL_PATTERN.findall(pattern):
                cleaned = literal.strip()
                if len(cleaned) >= 4:
                    literals.add(cleaned)
        return StixIndicatorSet(
            source_path=str(path),
            name=path.name,
            literals=sorted(literals),
            raw_indicator_count=indicator_count,
        )

    def _apple_notification_findings(self, path: Path) -> List[Finding]:
        text = self._safe_read_text(path)
        if not self._looks_like_apple_notification(text):
            return []
        return [Finding(
            rule_id='imported_apple_threat_notification',
            title='Imported Apple threat notification references mercenary spyware',
            family='High-Confidence External Signal',
            threat_level='high',
            author_or_actor='Apple',
            description=(
                'A locally imported artifact appears to contain an Apple threat notification about mercenary spyware targeting. '
                'This should be treated as a high-confidence external signal and investigated alongside host, backup, or sysdiagnose evidence.'
            ),
            evidence_type='artifact-text',
            source='intel',
            matched_path=str(path),
            matched_regex='Apple threat notification / mercenary spyware',
            confidence='high',
        )]

    def _backup_presence_findings(self, path: Path) -> List[Finding]:
        return [Finding(
            rule_id='ios_backup_imported',
            title='Imported iPhone or iPad backup for local forensic review',
            family='Forensic Intake',
            threat_level='low',
            author_or_actor='Mac Sentinel local intake',
            description='A local mobile backup was imported for offline review. This is context only until indicator or artifact matches are found.',
            evidence_type='artifact-container',
            source='intel',
            matched_path=str(path),
            matched_regex='Manifest.db / Info.plist / Status.plist',
            confidence='context',
        )]

    def _sysdiagnose_dir_findings(self, path: Path) -> List[Finding]:
        findings = [Finding(
            rule_id='ios_sysdiagnose_imported',
            title='Imported sysdiagnose-style directory for local forensic review',
            family='Forensic Intake',
            threat_level='low',
            author_or_actor='Mac Sentinel local intake',
            description='A local sysdiagnose-style artifact directory was imported for offline review. This is context only until stronger matches are found.',
            evidence_type='artifact-container',
            source='intel',
            matched_path=str(path),
            matched_regex='Shutdown.log present',
            confidence='context',
        )]
        shutdown = self._find_named_file(path, 'Shutdown.log')
        if shutdown:
            findings.extend(self._sysdiagnose_shutdown_findings(shutdown))
        return findings

    def _sysdiagnose_shutdown_findings(self, path: Path) -> List[Finding]:
        text = self._safe_read_text(path, max_bytes=2 * 1024 * 1024)
        hits = [pattern.pattern for pattern in SYSDIAG_CONTEXT_PATTERNS if pattern.search(text)]
        if not hits:
            return []
        return [Finding(
            rule_id='sysdiagnose_shutdown_exploit_surface_context',
            title='Imported sysdiagnose log references Messages / IDS exploit-surface processes',
            family='Exploit Surface Context',
            threat_level='low',
            author_or_actor='Forensic context only',
            description=(
                'The imported Shutdown.log contains references to Messages or IDS-related processes such as MessagesBlastDoorService or imagent. '
                'This is not proof of compromise by itself, but it is useful context when paired with threat notifications, unified log correlations, or IOC matches.'
            ),
            evidence_type='artifact-text',
            source='intel',
            matched_path=str(path),
            matched_regex='; '.join(hits),
            confidence='context',
        )]

    def _endpointsecurity_findings(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        events = self._parse_json_lines(path)
        suspicious_event_count = 0
        chain_signals: Dict[str, Set[str]] = {}
        for event in events[:2500]:
            normalized = self._normalize_es_event(event)
            if not normalized:
                continue
            event_type = normalized['event_type']
            process_path = normalized['process_path']
            target_path = normalized['target_path']
            rule_id = ''
            title = ''
            severity = 'low'
            description = ''
            matched = ''
            if event_type.endswith('EXEC') and self._looks_untrusted_exec(process_path, event):
                rule_id = 'endpointsecurity_untrusted_exec'
                title = 'EndpointSecurity export shows execution from an untrusted location'
                severity = 'mid'
                description = (
                    'An imported Endpoint Security event shows code execution from a temporary, download, or otherwise untrusted path. '
                    'This is useful triage context when paired with persistence writes, TCC activity, or suspicious network activity.'
                )
                matched = process_path
                chain_signals.setdefault(process_path, set()).add('exec')
            elif target_path and self._is_persistence_target(target_path):
                rule_id = 'endpointsecurity_persistence_or_sensitive_write'
                title = 'EndpointSecurity export shows access to persistence or sensitive policy data'
                severity = 'high' if 'TCC.db' in target_path or 'ConfigurationProfiles' in target_path else 'mid'
                description = (
                    'An imported Endpoint Security event references a launch agent, launch daemon, TCC database, configuration profile, '
                    'or another persistence-sensitive location. Review the surrounding event sequence carefully.'
                )
                matched = f'{event_type} -> {target_path}'
                chain_signals.setdefault(process_path or target_path, set()).add('sensitive-write')
            elif event_type.endswith('MMAP') and target_path and SUSPICIOUS_IMAGE_PATH.search(target_path):
                rule_id = 'endpointsecurity_suspicious_image_mapping'
                title = 'EndpointSecurity export shows image mapping from an unusual path'
                severity = 'mid'
                description = (
                    'An imported Endpoint Security event indicates that a process mapped an executable image or dylib from a temporary, user-download, '
                    'or container-like path. This can be legitimate, but it deserves review when combined with other suspicious indicators.'
                )
                matched = target_path
                chain_signals.setdefault(process_path or target_path, set()).add('mmap')

            if not rule_id:
                continue

            suspicious_event_count += 1
            findings.append(Finding(
                rule_id=rule_id,
                title=title,
                family='Endpoint Security Telemetry',
                threat_level=severity,
                author_or_actor='Imported EndpointSecurity telemetry',
                description=description,
                evidence_type='telemetry-jsonl',
                source='intel',
                matched_path=str(path),
                process_name=Path(process_path).name if process_path else '',
                process_cmdline=process_path,
                matched_regex=matched,
                confidence='signal' if severity == 'mid' else 'correlated',
            ))

        for chain_key, signals in list(chain_signals.items())[:50]:
            if {'exec', 'sensitive-write'}.issubset(signals):
                findings.append(Finding(
                    rule_id='endpointsecurity_exec_to_persistence_chain',
                    title='EndpointSecurity export suggests execution followed by persistence-sensitive activity',
                    family='Exploit Chain Reconstruction',
                    threat_level='high',
                    author_or_actor='Correlation-based triage',
                    description=(
                        'The imported Endpoint Security telemetry suggests a sequence where an executed binary was later associated with '
                        'persistence-sensitive or policy-sensitive file activity. This is higher priority than either signal alone.'
                    ),
                    evidence_type='correlation',
                    source='intel',
                    matched_path=str(path),
                    process_cmdline=chain_key,
                    matched_regex='exec + sensitive-write',
                    confidence='correlated',
                ))
            elif {'exec', 'mmap'}.issubset(signals):
                findings.append(Finding(
                    rule_id='endpointsecurity_exec_to_suspicious_mapping_chain',
                    title='EndpointSecurity export suggests execution followed by suspicious image mapping',
                    family='Exploit Chain Reconstruction',
                    threat_level='high',
                    author_or_actor='Correlation-based triage',
                    description=(
                        'The imported Endpoint Security telemetry suggests a process executed from an untrusted location and later '
                        'mapped an image from another unusual path. This is an elevated review case.'
                    ),
                    evidence_type='correlation',
                    source='intel',
                    matched_path=str(path),
                    process_cmdline=chain_key,
                    matched_regex='exec + mmap',
                    confidence='correlated',
                ))

        if suspicious_event_count >= 12:
            findings.append(Finding(
                rule_id='endpointsecurity_dense_suspicious_activity',
                title='EndpointSecurity export contains a dense cluster of suspicious activity',
                family='Endpoint Security Telemetry',
                threat_level='high',
                author_or_actor='Imported EndpointSecurity telemetry',
                description='A dense cluster of suspicious Endpoint Security events was observed in a single imported export. Review the timeline as a candidate incident rather than isolated events.',
                evidence_type='correlation',
                source='intel',
                matched_path=str(path),
                matched_regex=f'{suspicious_event_count} suspicious events',
                confidence='correlated',
            ))
        return findings

    def _unified_log_findings_from_file(self, path: Path) -> List[Finding]:
        entries = self._parse_json_lines(path)
        return self._unified_log_findings_from_entries(entries, source_label=str(path))

    def _unified_log_findings_from_entries(self, entries: Sequence[Dict], source_label: str) -> List[Finding]:
        findings: List[Finding] = []
        hits: Dict[str, int] = {}
        examples: Dict[str, str] = {}
        for entry in entries[:4000]:
            text = ' '.join(
                str(entry.get(key, ''))
                for key in ('eventMessage', 'composedMessage', 'message', 'subsystem', 'category', 'processImagePath', 'senderImagePath')
            )
            if not text.strip():
                continue
            for name, pattern in UNIFIED_LOG_SUSPICIOUS_PATTERNS:
                if pattern.search(text):
                    hits[name] = hits.get(name, 0) + 1
                    examples.setdefault(name, text[:400])

        if hits.get('messages_attack_surface_crash', 0) >= 2:
            findings.append(Finding(
                rule_id='unified_log_messages_attack_surface_burst',
                title='Unified logs show repeated activity in Messages / IDS attack-surface processes',
                family='Unified Log Correlation',
                threat_level='mid',
                author_or_actor='Imported host telemetry',
                description=(
                    'Unified logs contain repeated activity referencing MessagesBlastDoorService, imagent, identityservicesd, or WebContent. '
                    'This is contextual until paired with stronger host or forensic signals, but it is useful in high-risk triage.'
                ),
                evidence_type='unified-log',
                source='intel',
                matched_path=source_label,
                matched_regex=examples.get('messages_attack_surface_crash', ''),
                confidence='signal',
            ))
        if hits.get('tcc_change', 0) >= 2:
            findings.append(Finding(
                rule_id='unified_log_tcc_context',
                title='Unified logs reference TCC or privacy-control activity',
                family='Unified Log Correlation',
                threat_level='mid',
                author_or_actor='Imported host telemetry',
                description='Unified logs reference TCC-related decisions or privacy-control activity. Combine this with file, persistence, or Endpoint Security evidence before escalating.',
                evidence_type='unified-log',
                source='intel',
                matched_path=source_label,
                matched_regex=examples.get('tcc_change', ''),
                confidence='signal',
            ))
        if hits.get('profile_change', 0) >= 1:
            findings.append(Finding(
                rule_id='unified_log_profile_context',
                title='Unified logs reference configuration profile activity',
                family='Unified Log Correlation',
                threat_level='mid',
                author_or_actor='Imported host telemetry',
                description='Unified logs reference configuration-profile installation, removal, or MDM-related actions. Review carefully if the host was not expected to enroll or receive new profiles.',
                evidence_type='unified-log',
                source='intel',
                matched_path=source_label,
                matched_regex=examples.get('profile_change', ''),
                confidence='signal',
            ))
        if hits.get('messages_attack_surface_crash', 0) and hits.get('tcc_change', 0):
            findings.append(Finding(
                rule_id='unified_log_attack_surface_plus_tcc_chain',
                title='Unified logs show attack-surface activity plus TCC-related context',
                family='Exploit Chain Reconstruction',
                threat_level='high',
                author_or_actor='Correlation-based triage',
                description='Unified logs show both attack-surface process activity and TCC-related context in the same collection window. This should be prioritized for manual review.',
                evidence_type='correlation',
                source='intel',
                matched_path=source_label,
                matched_regex='messages/ids + tcc',
                confidence='correlated',
            ))
        return findings

    def _memory_artifact_findings(self, path: Path, kind: str) -> List[Finding]:
        text = self._safe_read_text(path, max_bytes=3 * 1024 * 1024)
        if not text:
            return []
        findings: List[Finding] = []
        marker_hits = [pattern.pattern for pattern in SUSPICIOUS_MEMORY_MARKERS if pattern.search(text)]
        image_hits = sorted(set(match.group(1) for match in SUSPICIOUS_IMAGE_PATH.finditer(text)))
        if marker_hits:
            findings.append(Finding(
                rule_id='memory_artifact_suspicious_api_marker',
                title='Memory-analysis artifact references suspicious injection or inspection APIs',
                family='Memory Forensics',
                threat_level='high',
                author_or_actor='Offline memory-analysis parser',
                description=(
                    'The imported memory-analysis artifact references APIs or strings commonly associated with dynamic injection, '
                    'debugging, or process memory inspection. This is not conclusive on its own, but it is a strong manual-review lead.'
                ),
                evidence_type=kind,
                source='intel',
                matched_path=str(path),
                matched_regex=', '.join(marker_hits[:6]),
                confidence='correlated',
            ))
        if re.search(r'\brwx\b|write/execute|W\+X', text, re.I):
            findings.append(Finding(
                rule_id='memory_artifact_wx_pages',
                title='Memory-analysis artifact references writable-and-executable memory',
                family='Memory Forensics',
                threat_level='high',
                author_or_actor='Offline memory-analysis parser',
                description='The imported memory-analysis artifact appears to reference writable-and-executable memory. That can be benign in some runtimes, but it is important context during targeted-attack triage.',
                evidence_type=kind,
                source='intel',
                matched_path=str(path),
                matched_regex='rwx / W+X marker',
                confidence='signal',
            ))
        if image_hits:
            findings.append(Finding(
                rule_id='memory_artifact_unusual_image_path',
                title='Memory-analysis artifact references images from unusual paths',
                family='Memory Forensics',
                threat_level='mid',
                author_or_actor='Offline memory-analysis parser',
                description='The imported memory-analysis artifact references one or more images from temporary, download, or container-like paths. Review whether those modules are expected for the process being analyzed.',
                evidence_type=kind,
                source='intel',
                matched_path=str(path),
                matched_regex=', '.join(image_hits[:4]),
                confidence='signal',
            ))
        return findings

    def _crash_report_findings(self, path: Path) -> List[Finding]:
        text = self._safe_read_text(path, max_bytes=1024 * 1024)
        if not text:
            return []
        if not re.search(r'(MessagesBlastDoorService|imagent|identityservicesd|WebContent)', text, re.I):
            return []
        reason = re.search(r'Exception Type:\s*(.+)', text)
        return [Finding(
            rule_id='crash_report_attack_surface_context',
            title='Crash report references a common targeted-attack surface process',
            family='Advanced Forensic Parsing',
            threat_level='mid',
            author_or_actor='Crash report parser',
            description=(
                'The imported crash report references a process that often appears in triage for messaging, identity, or content-rendering attack surfaces. '
                'This is context, not proof of compromise, but it becomes more valuable when correlated with logs, profiles, or indicators.'
            ),
            evidence_type='crash-report',
            source='intel',
            matched_path=str(path),
            matched_regex=reason.group(1).strip() if reason else 'attack-surface process',
            confidence='context',
        )]

    def _diagnostic_index_findings(self, reports: Sequence[Dict]) -> List[Finding]:
        counts: Dict[str, int] = {}
        for item in reports:
            process = str(item.get('process', '')).lower()
            if process:
                counts[process] = counts.get(process, 0) + 1
        findings: List[Finding] = []
        for process, count in counts.items():
            if count >= 2 and process in {'messagesblastdoorservice', 'imagent', 'identityservicesd', 'webkit'}:
                findings.append(Finding(
                    rule_id='diagnostic_report_attack_surface_burst',
                    title='Recent diagnostic reports show a burst in an attack-surface process',
                    family='Advanced Forensic Parsing',
                    threat_level='mid',
                    author_or_actor='Crash report index parser',
                    description=f'Recent diagnostic reports include {count} entries for {process}. This is context that should be reviewed alongside stronger telemetry or forensic indicators.',
                    evidence_type='diagnostic-report-index',
                    source='intel',
                    matched_regex=f'{process}: {count}',
                    confidence='signal',
                ))
        return findings

    def _directory_stix_match_findings(self, root: Path, kind: str) -> List[Finding]:
        findings: List[Finding] = []
        for candidate in self._iter_text_files(root):
            findings.extend(self._stix_match_findings(candidate, root_label=kind))
            if candidate.name == 'Shutdown.log':
                findings.extend(self._sysdiagnose_shutdown_findings(candidate))
            if len(findings) >= 80:
                break
        return findings

    def _stix_match_findings(self, path: Path, root_label: str) -> List[Finding]:
        findings: List[Finding] = []
        if not self._stix_sets:
            return findings
        text = self._safe_read_text(path)
        if not text:
            return findings
        lowered_text = text.lower()
        lowered_path = str(path).lower()
        for stix_set in self._stix_sets:
            matched_literals = []
            for literal in stix_set.literals:
                lowered_literal = literal.lower()
                if lowered_literal in lowered_text or lowered_literal in lowered_path:
                    matched_literals.append(literal)
                if len(matched_literals) >= 3:
                    break
            if matched_literals:
                severity = 'high' if root_label in {'backup', 'sysdiagnose', 'sysdiagnose-log', 'endpointsecurity-jsonl', 'unified-log-json'} else 'mid'
                findings.append(Finding(
                    rule_id='stix_indicator_match_in_imported_artifact',
                    title='Imported artifact matched a locally loaded STIX indicator',
                    family='Indicator Match',
                    threat_level=severity,
                    author_or_actor=f'STIX source: {stix_set.name}',
                    description=(
                        f'The imported artifact {path} matched one or more literals extracted from the STIX indicator set {stix_set.name}. '
                        'This is a stronger signal than broad host keyword scans because it is scoped to user-selected forensic artifacts and explicit indicator feeds.'
                    ),
                    evidence_type='stix-match',
                    source='intel',
                    matched_path=str(path),
                    matched_regex=', '.join(matched_literals),
                    confidence='high' if severity == 'high' else 'signal',
                ))
        return findings

    def _correlate_intel_findings(self, findings: Sequence[Finding]) -> List[Finding]:
        rule_ids = {item.rule_id for item in findings}
        has_apple_notification = 'imported_apple_threat_notification' in rule_ids
        has_stix = 'stix_indicator_match_in_imported_artifact' in rule_ids
        has_sysdiagnose_context = 'sysdiagnose_shutdown_exploit_surface_context' in rule_ids
        has_endpoint_chain = bool(rule_ids.intersection({'endpointsecurity_exec_to_persistence_chain', 'endpointsecurity_exec_to_suspicious_mapping_chain'}))
        has_memory = bool(rule_ids.intersection({'memory_artifact_suspicious_api_marker', 'memory_artifact_wx_pages', 'memory_artifact_unusual_image_path'}))
        has_unified_logs = bool(rule_ids.intersection({'unified_log_messages_attack_surface_burst', 'unified_log_tcc_context', 'unified_log_profile_context', 'unified_log_attack_surface_plus_tcc_chain'}))
        correlated: List[Finding] = []
        if has_apple_notification and has_stix:
            correlated.append(Finding(
                rule_id='correlated_apple_notification_plus_stix',
                title='Apple threat notification and STIX match observed together',
                family='Correlation / High-Confidence Review Priority',
                threat_level='high',
                author_or_actor='Correlation-based triage',
                description='An imported Apple threat notification and a locally matched STIX indicator were observed together. This combination should be treated as a high-priority investigation case.',
                evidence_type='correlation',
                source='intel',
                matched_regex='apple notification + stix',
                confidence='high',
            ))
        if has_sysdiagnose_context and has_stix:
            correlated.append(Finding(
                rule_id='correlated_sysdiagnose_plus_stix',
                title='Sysdiagnose context and STIX match observed together',
                family='Correlation / Elevated Review Priority',
                threat_level='high',
                author_or_actor='Correlation-based triage',
                description='Imported sysdiagnose context and a local STIX match were observed together. This is stronger than either signal alone and deserves manual review.',
                evidence_type='correlation',
                source='intel',
                matched_regex='sysdiagnose + stix',
                confidence='correlated',
            ))
        if has_endpoint_chain and has_memory:
            correlated.append(Finding(
                rule_id='correlated_endpoint_chain_plus_memory',
                title='EndpointSecurity chain and memory-analysis signals observed together',
                family='Correlation / Elevated Review Priority',
                threat_level='high',
                author_or_actor='Correlation-based triage',
                description='An imported Endpoint Security event sequence and memory-analysis signal were observed together. This is materially stronger than either artifact on its own.',
                evidence_type='correlation',
                source='intel',
                matched_regex='endpoint chain + memory',
                confidence='correlated',
            ))
        if has_unified_logs and has_endpoint_chain:
            correlated.append(Finding(
                rule_id='correlated_unified_logs_plus_endpoint_chain',
                title='Unified log context and EndpointSecurity chain observed together',
                family='Exploit Chain Reconstruction',
                threat_level='high',
                author_or_actor='Correlation-based triage',
                description='Unified logs and imported Endpoint Security telemetry both point to related suspicious activity in the same review set. Treat this as a candidate incident timeline, not isolated findings.',
                evidence_type='correlation',
                source='intel',
                matched_regex='unified logs + endpoint chain',
                confidence='correlated',
            ))
        return correlated

    def _dedupe_findings(self, findings: Sequence[Finding]) -> List[Finding]:
        seen: Set[Tuple[str, str, str]] = set()
        unique: List[Finding] = []
        for item in findings:
            key = (item.rule_id, item.matched_path, item.matched_regex)
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        return unique

    def _safe_read_text(self, path: Path, max_bytes: int = 1024 * 1024) -> str:
        try:
            if path.stat().st_size > max_bytes:
                return ''
            return path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return ''

    def _parse_json_lines(self, path: Path) -> List[Dict]:
        text = self._safe_read_text(path, max_bytes=5 * 1024 * 1024)
        if not text:
            return []
        stripped = text.strip()
        if not stripped:
            return []
        if stripped.startswith('['):
            try:
                payload = json.loads(stripped)
                return [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []
            except Exception:
                return []
        if stripped.startswith('{') and '\n' not in stripped:
            try:
                payload = json.loads(stripped)
                return [payload] if isinstance(payload, dict) else []
            except Exception:
                return []
        rows: List[Dict] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or not line.startswith('{'):
                continue
            try:
                payload = json.loads(line)
            except Exception:
                continue
            if isinstance(payload, dict):
                rows.append(payload)
        return rows

    def _normalize_es_event(self, event: Dict) -> Dict | None:
        event_type = str(event.get('event_type') or event.get('eventType') or event.get('type') or '').upper()
        if not event_type:
            return None
        if event_type not in ENDPOINT_EVENT_CANDIDATES and not any(token in event_type for token in ('EXEC', 'OPEN', 'CREATE', 'WRITE', 'RENAME', 'UNLINK', 'MMAP')):
            return None
        process = event.get('process') if isinstance(event.get('process'), dict) else {}
        target = event.get('target') if isinstance(event.get('target'), dict) else {}
        process_path = str(
            process.get('path') or process.get('executable') or event.get('process_path') or event.get('processPath') or ''
        )
        target_path = str(
            target.get('path') or event.get('target_path') or event.get('targetPath') or event.get('path') or event.get('destination_path') or ''
        )
        return {
            'event_type': event_type,
            'process_path': process_path,
            'target_path': target_path,
        }

    def _looks_untrusted_exec(self, process_path: str, raw_event: Dict) -> bool:
        if not process_path:
            return False
        lower = process_path.lower()
        if any(token in lower for token in ('/tmp/', '/var/tmp/', '/downloads/', '/private/var/folders/')):
            return True
        signing_id = str(raw_event.get('signing_id') or raw_event.get('signingId') or raw_event.get('team_id') or '')
        if not signing_id and lower.startswith('/users/'):
            return True
        return False

    def _is_persistence_target(self, target_path: str) -> bool:
        if not target_path:
            return False
        if any(token in target_path for token in SUSPICIOUS_PERSISTENCE_PATHS):
            return True
        return any(target_path.endswith(suffix) or suffix in target_path for suffix in SUSPICIOUS_USER_PERSISTENCE_SUFFIXES)

    def _looks_like_apple_notification(self, text: str) -> bool:
        return all(pattern.search(text or '') for pattern in APPLE_NOTIFICATION_PATTERNS[:2]) or APPLE_NOTIFICATION_PATTERNS[2].search(text or '') is not None

    def _directory_contains(self, root: Path, names: Iterable[str]) -> bool:
        wanted = set(names)
        try:
            for current_root, _, files in os.walk(root):
                if wanted.intersection(files):
                    return True
        except Exception:
            return False
        return False

    def _find_named_file(self, root: Path, name: str) -> Path | None:
        try:
            for current_root, _, files in os.walk(root):
                if name in files:
                    return Path(current_root) / name
        except Exception:
            return None
        return None

    def _iter_text_files(self, root: Path) -> Iterable[Path]:
        try:
            for current_root, dirs, files in os.walk(root):
                dirs[:] = [item for item in dirs if item not in {'node_modules', '.git', '.venv', '__pycache__'}]
                for name in files:
                    candidate = Path(current_root) / name
                    if candidate.suffix.lower() in TEXT_EXTENSIONS or candidate.name in BACKUP_MARKERS or candidate.name in SYSDIAG_MARKERS:
                        yield candidate
        except Exception:
            return
