from __future__ import annotations

import os
import tempfile
import time
import uuid
from pathlib import Path
from threading import Condition, RLock
from typing import Dict, List, Optional

from ..config import settings
from .local_storage import LocalStorage


class AppStateStore:
    """Thread-safe application state with bounded local persistence.

    Status objects and current findings remain in memory for fast access. Long-lived logs,
    monitor events, and snapshots are stored in a local SQLite ring buffer so the UI can run
    for long sessions without growing memory indefinitely.
    """

    def __init__(self, storage: Optional[LocalStorage] = None):
        self._lock = RLock()
        self._condition = Condition(self._lock)
        default_storage = storage
        if default_storage is None:
            if os.getenv('PYTEST_CURRENT_TEST'):
                test_db = Path(tempfile.mkdtemp(prefix='mac_sentinel_state_')) / f'{uuid.uuid4().hex}.db'
                default_storage = LocalStorage(test_db)
            else:
                default_storage = LocalStorage(settings.local_db_path)
        self._storage = default_storage
        self._scan_findings: List[Dict] = []
        self._monitor_connections: List[Dict] = self._storage.get_snapshot('monitor_connections', default=[]) or []
        self._intel_summary: Dict = self._storage.get_snapshot('intelligence_summary', default={}) or {}
        self._intel_artifacts: List[Dict] = self._storage.get_snapshot('intelligence_artifacts', default=[]) or []
        self._intel_findings: List[Dict] = self._storage.get_snapshot('intelligence_findings', default=[]) or []
        self._protection_status = self._storage.get_snapshot('protection_status', default=None) or {
            'enabled': False,
            'running': False,
            'mode': 'protect',
            'last_started': None,
            'last_cycle': None,
            'event_count': len(self._storage.list_entries('protection_events', settings.protection_event_retention)),
            'blocked_count': 0,
            'quarantined_count': 0,
            'watched_path_count': 0,
            'local_only': True,
            'error': '',
        }
        self._scan_status = {
            'running': False,
            'paused': False,
            'stop_requested': False,
            'cancelled': False,
            'last_started': None,
            'last_finished': None,
            'count': 0,
            'error': '',
            'total_rules': 0,
            'scanned_rules': 0,
            'current_rule': '',
            'progress_percent': 0,
        }
        self._monitor_status = {
            'running': False,
            'last_started': None,
            'event_count': len(self.live_events()),
            'last_cycle': None,
            'observed_connection_count': len(self._monitor_connections),
            'error': '',
        }
        self._revisions = {
            'scan_status': 0,
            'scan_findings': 0,
            'scan_logs': 0,
            'monitor_status': 0,
            'monitor_events': 0,
            'monitor_logs': 0,
            'monitor_connections': 0,
            'intelligence_findings': 0,
            'intelligence_artifacts': 0,
            'intelligence_logs': 0,
            'intelligence_summary': 0,
            'protection_status': 0,
            'protection_events': 0,
            'protection_logs': 0,
        }

    def _bump(self, *names: str) -> None:
        for name in names:
            self._revisions[name] += 1
        self._condition.notify_all()

    def revisions(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._revisions)

    def wait_for_revision_change(self, previous: Optional[Dict[str, int]] = None, timeout: Optional[float] = None) -> Dict[str, int]:
        timeout = float(timeout or settings.sse_wait_seconds)
        with self._condition:
            if not previous:
                return dict(self._revisions)
            changed = any(self._revisions.get(key) != previous.get(key) for key in self._revisions)
            if not changed:
                self._condition.wait(timeout=timeout)
            return dict(self._revisions)

    def _log_entry(self, level: str, message: str, phase: str = '', extra: Optional[Dict] = None) -> Dict:
        payload = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'level': level,
            'phase': phase,
            'message': message,
        }
        if extra:
            payload.update(extra)
        return payload

    def _append_ring_log(self, category: str, retention: int, message: str, level: str = 'info', phase: str = '', extra: Optional[Dict] = None) -> None:
        payload = self._log_entry(level, message, phase, extra)
        self._storage.append_entry(category, payload, retention=retention)

    def begin_scan(self, total_rules: int = 0, clear_logs: bool = True) -> None:
        with self._condition:
            if clear_logs:
                self._storage.clear_entries('scan_logs')
                self._bump('scan_logs')
            self._scan_status.update({
                'running': True,
                'paused': False,
                'stop_requested': False,
                'cancelled': False,
                'last_started': time.strftime('%Y-%m-%d %H:%M:%S'),
                'last_finished': None,
                'error': '',
                'count': 0,
                'total_rules': total_rules,
                'scanned_rules': 0,
                'current_rule': '',
                'progress_percent': 0,
            })
            self._bump('scan_status')

    def pause_scan(self) -> None:
        with self._condition:
            if self._scan_status['running']:
                self._scan_status['paused'] = True
                self._append_ring_log('scan_logs', settings.scan_log_retention, 'Scan paused by user.', phase='pause')
                self._bump('scan_status', 'scan_logs')

    def resume_scan(self) -> None:
        with self._condition:
            if self._scan_status['running']:
                self._scan_status['paused'] = False
                self._append_ring_log('scan_logs', settings.scan_log_retention, 'Scan resumed by user.', phase='resume')
                self._bump('scan_status', 'scan_logs')

    def request_stop_scan(self) -> None:
        with self._condition:
            if self._scan_status['running']:
                self._scan_status['stop_requested'] = True
                self._append_ring_log('scan_logs', settings.scan_log_retention, 'Scan stop requested. The current check will exit safely.', level='warning', phase='stop-request')
                self._bump('scan_status', 'scan_logs')

    def cancel_scan(self) -> None:
        with self._condition:
            self._scan_status.update({
                'running': False,
                'paused': False,
                'stop_requested': False,
                'cancelled': True,
                'last_finished': time.strftime('%Y-%m-%d %H:%M:%S'),
                'current_rule': '',
            })
            self._append_ring_log('scan_logs', settings.scan_log_retention, 'Scan cancelled before completion.', level='warning', phase='cancelled')
            self._bump('scan_status', 'scan_logs')

    def update_scan_progress(self, scanned_rules: int, total_rules: int, current_rule: str = '') -> None:
        with self._condition:
            progress = int((scanned_rules / total_rules) * 100) if total_rules else 0
            next_status = {
                'scanned_rules': scanned_rules,
                'total_rules': total_rules,
                'current_rule': current_rule,
                'progress_percent': max(0, min(100, progress)),
            }
            changed = any(self._scan_status.get(key) != value for key, value in next_status.items())
            self._scan_status.update(next_status)
            if changed:
                self._bump('scan_status')

    def append_scan_log(self, message: str, level: str = 'info', phase: str = '', extra: Optional[Dict] = None, limit: Optional[int] = None) -> None:
        with self._condition:
            self._append_ring_log('scan_logs', limit or settings.scan_log_retention, message, level=level, phase=phase, extra=extra)
            self._bump('scan_logs')

    def fail_scan(self, error: str) -> None:
        with self._condition:
            self._scan_status.update({
                'running': False,
                'paused': False,
                'stop_requested': False,
                'last_finished': time.strftime('%Y-%m-%d %H:%M:%S'),
                'error': error,
                'current_rule': '',
            })
            self._append_ring_log('scan_logs', settings.scan_log_retention, f'Scan failed: {error}', level='error', phase='error')
            self._bump('scan_status', 'scan_logs')

    def set_scan_results(self, findings: List[Dict]) -> None:
        with self._condition:
            total_rules = self._scan_status.get('total_rules', 0)
            self._scan_findings = findings
            self._scan_status.update({
                'running': False,
                'paused': False,
                'stop_requested': False,
                'cancelled': False,
                'last_finished': time.strftime('%Y-%m-%d %H:%M:%S'),
                'count': len(findings),
                'error': '',
                'scanned_rules': total_rules,
                'current_rule': '',
                'progress_percent': 100 if total_rules else 0,
            })
            self._bump('scan_findings', 'scan_status')

    def scan_status(self) -> Dict:
        with self._lock:
            return dict(self._scan_status)

    def scan_findings(self) -> List[Dict]:
        with self._lock:
            return list(self._scan_findings)

    def scan_logs(self) -> List[Dict]:
        return self._storage.list_entries('scan_logs', settings.scan_log_retention)

    def get_finding(self, source: str, finding_id: str) -> Optional[Dict]:
        with self._lock:
            if source == 'live':
                collection = self.live_events()
            elif source == 'intel':
                collection = self._intel_findings
            elif source == 'protect':
                collection = self.protection_events()
            else:
                collection = self._scan_findings
            for item in collection:
                if item.get('finding_id') == finding_id:
                    return dict(item)
        return None

    def append_live_events(self, events: List[Dict], limit: Optional[int] = None) -> None:
        retention = limit or settings.monitor_event_retention
        with self._condition:
            for item in events:
                fingerprint = item.get('finding_id') or ''
                self._storage.append_entry('monitor_events', item, retention=retention, fingerprint=fingerprint)
            self._monitor_status['event_count'] = len(self.live_events())
            self._bump('monitor_events', 'monitor_status')

    def clear_live_events(self) -> None:
        with self._condition:
            self._storage.clear_entries('monitor_events')
            self._monitor_status['event_count'] = 0
            self._bump('monitor_events', 'monitor_status')

    def live_events(self) -> List[Dict]:
        return self._storage.list_entries('monitor_events', settings.monitor_event_retention)

    def append_monitor_log(self, message: str, level: str = 'info', phase: str = '', extra: Optional[Dict] = None, limit: Optional[int] = None) -> None:
        with self._condition:
            self._append_ring_log('monitor_logs', limit or settings.monitor_log_retention, message, level=level, phase=phase, extra=extra)
            self._bump('monitor_logs')

    def monitor_logs(self) -> List[Dict]:
        return self._storage.list_entries('monitor_logs', settings.monitor_log_retention)

    def clear_monitor_logs(self) -> None:
        with self._condition:
            self._storage.clear_entries('monitor_logs')
            self._bump('monitor_logs')

    def set_monitor_running(self, running: bool) -> None:
        with self._condition:
            changed = self._monitor_status['running'] != running
            self._monitor_status['running'] = running
            self._monitor_status['error'] = ''
            if running:
                self._monitor_status['last_started'] = time.strftime('%Y-%m-%d %H:%M:%S')
                changed = True
            if changed:
                self._bump('monitor_status')

    def update_monitor_cycle(self, observed_connection_count: int) -> None:
        with self._condition:
            next_values = {
                'last_cycle': time.strftime('%Y-%m-%d %H:%M:%S'),
                'observed_connection_count': observed_connection_count,
            }
            changed = any(self._monitor_status.get(key) != value for key, value in next_values.items())
            self._monitor_status.update(next_values)
            if changed:
                self._bump('monitor_status')

    def set_monitor_connections(self, connections: List[Dict]) -> bool:
        with self._condition:
            trimmed = list(connections)[:settings.monitor_connection_retention]
            if self._monitor_connections == trimmed:
                return False
            self._monitor_connections = trimmed
            self._storage.set_snapshot('monitor_connections', trimmed)
            self._bump('monitor_connections')
            return True

    def monitor_connections(self) -> List[Dict]:
        with self._lock:
            return list(self._monitor_connections)

    def fail_monitor(self, error: str) -> None:
        with self._condition:
            self._monitor_status.update({'running': False, 'error': error})
            self._append_ring_log('monitor_logs', settings.monitor_log_retention, f'Monitor error: {error}', level='error', phase='error')
            self._bump('monitor_status', 'monitor_logs')

    def monitor_status(self) -> Dict:
        with self._lock:
            return dict(self._monitor_status)


    def set_protection_config(self, enabled: bool, mode: str = 'protect') -> None:
        with self._condition:
            changed = self._protection_status.get('enabled') != bool(enabled) or self._protection_status.get('mode') != str(mode or 'protect')
            self._protection_status['enabled'] = bool(enabled)
            self._protection_status['mode'] = str(mode or 'protect')
            self._storage.set_snapshot('protection_status', self._protection_status)
            if changed:
                self._bump('protection_status')

    def set_protection_running(self, running: bool, watched_path_count: Optional[int] = None) -> None:
        with self._condition:
            changed = self._protection_status.get('running') != bool(running)
            self._protection_status['running'] = bool(running)
            self._protection_status['error'] = ''
            if watched_path_count is not None:
                self._protection_status['watched_path_count'] = int(max(0, watched_path_count))
                changed = True
            if running:
                self._protection_status['last_started'] = time.strftime('%Y-%m-%d %H:%M:%S')
                changed = True
            self._storage.set_snapshot('protection_status', self._protection_status)
            if changed:
                self._bump('protection_status')

    def update_protection_cycle(self, observed_events: int = 0) -> None:
        with self._condition:
            next_values = {
                'last_cycle': time.strftime('%Y-%m-%d %H:%M:%S'),
                'event_count': len(self.protection_events()),
            }
            changed = any(self._protection_status.get(key) != value for key, value in next_values.items())
            self._protection_status.update(next_values)
            self._storage.set_snapshot('protection_status', self._protection_status)
            if changed:
                self._bump('protection_status')

    def record_protection_actions(self, blocked_delta: int = 0, quarantined_delta: int = 0) -> None:
        with self._condition:
            self._protection_status['blocked_count'] = int(self._protection_status.get('blocked_count', 0)) + int(max(0, blocked_delta))
            self._protection_status['quarantined_count'] = int(self._protection_status.get('quarantined_count', 0)) + int(max(0, quarantined_delta))
            self._storage.set_snapshot('protection_status', self._protection_status)
            self._bump('protection_status')

    def append_protection_events(self, events: List[Dict], limit: Optional[int] = None) -> None:
        retention = limit or settings.protection_event_retention
        with self._condition:
            for item in events:
                fingerprint = item.get('finding_id') or ''
                self._storage.append_entry('protection_events', item, retention=retention, fingerprint=fingerprint)
            self._protection_status['event_count'] = len(self.protection_events())
            self._storage.set_snapshot('protection_status', self._protection_status)
            self._bump('protection_events', 'protection_status')

    def clear_protection_events(self) -> None:
        with self._condition:
            self._storage.clear_entries('protection_events')
            self._protection_status['event_count'] = 0
            self._storage.set_snapshot('protection_status', self._protection_status)
            self._bump('protection_events', 'protection_status')

    def protection_events(self) -> List[Dict]:
        return self._storage.list_entries('protection_events', settings.protection_event_retention)

    def append_protection_log(self, message: str, level: str = 'info', phase: str = '', extra: Optional[Dict] = None, limit: Optional[int] = None) -> None:
        with self._condition:
            self._append_ring_log('protection_logs', limit or settings.protection_log_retention, message, level=level, phase=phase, extra=extra)
            self._bump('protection_logs')

    def protection_logs(self) -> List[Dict]:
        return self._storage.list_entries('protection_logs', settings.protection_log_retention)

    def fail_protection(self, error: str) -> None:
        with self._condition:
            self._protection_status.update({'running': False, 'error': error})
            self._storage.set_snapshot('protection_status', self._protection_status)
            self._append_ring_log('protection_logs', settings.protection_log_retention, f'Active protection error: {error}', level='error', phase='error')
            self._bump('protection_status', 'protection_logs')

    def protection_status(self) -> Dict:
        with self._lock:
            return dict(self._protection_status)

    def set_intelligence_snapshot(self, artifacts: List[Dict], findings: List[Dict], summary: Dict) -> None:
        with self._condition:
            self._intel_artifacts = list(artifacts)[:settings.intelligence_artifact_retention]
            self._intel_findings = list(findings)[:settings.intelligence_finding_retention]
            self._intel_summary = dict(summary)
            self._storage.set_snapshot('intelligence_artifacts', self._intel_artifacts)
            self._storage.set_snapshot('intelligence_findings', self._intel_findings)
            self._storage.set_snapshot('intelligence_summary', self._intel_summary)
            self._bump('intelligence_artifacts', 'intelligence_findings', 'intelligence_summary')

    def append_intelligence_log(self, message: str, level: str = 'info', phase: str = '', extra: Optional[Dict] = None) -> None:
        with self._condition:
            self._append_ring_log('intelligence_logs', settings.intelligence_log_retention, message, level=level, phase=phase, extra=extra)
            self._bump('intelligence_logs')

    def clear_intelligence(self) -> None:
        with self._condition:
            self._intel_artifacts = []
            self._intel_findings = []
            self._intel_summary = {}
            self._storage.clear_entries('intelligence_logs')
            self._storage.set_snapshot('intelligence_artifacts', [])
            self._storage.set_snapshot('intelligence_findings', [])
            self._storage.set_snapshot('intelligence_summary', {})
            self._bump('intelligence_artifacts', 'intelligence_findings', 'intelligence_logs', 'intelligence_summary')

    def intelligence_artifacts(self) -> List[Dict]:
        with self._lock:
            return list(self._intel_artifacts)

    def intelligence_findings(self) -> List[Dict]:
        with self._lock:
            return list(self._intel_findings)

    def intelligence_logs(self) -> List[Dict]:
        return self._storage.list_entries('intelligence_logs', settings.intelligence_log_retention)

    def intelligence_summary(self) -> Dict:
        with self._lock:
            return dict(self._intel_summary)
