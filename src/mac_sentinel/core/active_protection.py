from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..config import settings
from ..models import Finding


class ActiveProtectionService:
    SUSPICIOUS_PORTS = {4444, 5555, 6667, 1337, 31337, 9001}
    COMMON_PORTS = {22, 53, 80, 123, 443, 465, 587, 631, 993, 995}
    SUSPICIOUS_EXTENSIONS = {
        '.app', '.command', '.dmg', '.js', '.jse', '.ksh', '.osa', '.osascript', '.pkg', '.plist', '.pl', '.py', '.rb',
        '.scpt', '.scptd', '.sh', '.tool', '.workflow', '.zip'
    }
    SUSPICIOUS_CMD = re.compile(
        r'(?i)(curl\s+https?://|wget\s+https?://|osascript|python\s+-c|perl\s+-e|ruby\s+-e|base64\s+-d|chmod\s+\+x|launchctl\s+(load|bootstrap)|security\s+add-|sqlite3\s+.*TCC\.db|do shell script|display dialog.*password)'
    )
    USER_WRITABLE_SEGMENTS = ('/downloads/', '/desktop/', '/tmp/', '/private/var/tmp/', '/users/', '/var/folders/')
    PERSISTENCE_SEGMENTS = ('/library/launchagents/', '/library/launchdaemons/')

    def __init__(self, collector, scan_service, state_store, remediation, storage, interval_seconds: int = 4):
        self.collector = collector
        self.scan_service = scan_service
        self.state_store = state_store
        self.remediation = remediation
        self.storage = storage
        self.interval_seconds = max(2, int(interval_seconds or 4))
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._recent_event_keys: Dict[Tuple, float] = {}
        self._recent_file_hits: Dict[str, float] = {}
        self._recent_proc_hits: Dict[int, float] = {}
        self._process_baseline: Dict[int, Dict] = {}
        self._launchd_baseline: Dict[str, Dict] = {}
        self._connection_baseline: Dict[str, Dict] = {}
        self._file_baseline: Dict[str, Dict] = {}
        self._config = self.storage.get_snapshot('active_protection_config', default=self._default_config()) or self._default_config()
        self.state_store.set_protection_config(bool(self._config.get('enabled', False)), mode=str(self._config.get('mode', 'protect')))
        if self._config.get('enabled'):
            self.start()

    def _default_config(self) -> Dict:
        return {
            'enabled': False,
            'mode': 'protect',
            'local_only': True,
            'watch_paths': self.default_watch_paths(),
        }

    def default_watch_paths(self) -> List[str]:
        home = str(Path.home())
        return [
            f'{home}/Downloads',
            f'{home}/Desktop',
            f'{home}/Library/LaunchAgents',
            '/Library/LaunchAgents',
            '/Library/LaunchDaemons',
            '/tmp',
            '/private/var/tmp',
        ]

    def config(self) -> Dict:
        return dict(self._config)

    def status(self) -> Dict:
        return self.state_store.protection_status()

    def start(self) -> bool:
        if self._thread and self._thread.is_alive():
            return False
        self._config['enabled'] = True
        self.storage.set_snapshot('active_protection_config', self._config)
        self.state_store.set_protection_config(True, mode=str(self._config.get('mode', 'protect')))
        self._stop_event.clear()
        self._prime_baselines()
        watch_count = len(self._existing_watch_paths())
        self.state_store.set_protection_running(True, watched_path_count=watch_count)
        self.state_store.append_protection_log(
            'Active protection enabled. Monitoring new processes, suspicious file drops, launchd persistence locations, and outbound network changes. All telemetry and response actions stay local to this Mac.',
            phase='start',
        )
        self._thread = threading.Thread(target=self._run, name='mac-sentinel-protection', daemon=True)
        self._thread.start()
        return True

    def stop(self) -> bool:
        if not self._thread:
            self._config['enabled'] = False
            self.storage.set_snapshot('active_protection_config', self._config)
            self.state_store.set_protection_config(False, mode=str(self._config.get('mode', 'protect')))
            self.state_store.set_protection_running(False)
            return False
        self._config['enabled'] = False
        self.storage.set_snapshot('active_protection_config', self._config)
        self.state_store.set_protection_config(False, mode=str(self._config.get('mode', 'protect')))
        self._stop_event.set()
        self.state_store.set_protection_running(False)
        self.state_store.append_protection_log('Active protection stopping.', phase='stop')
        return True

    def _prime_baselines(self) -> None:
        try:
            self._process_baseline = {item['pid']: item for item in self.collector.collect_processes(fresh=True)}
        except Exception:
            self._process_baseline = {}
        try:
            self._launchd_baseline = {item['label']: item for item in self.collector.collect_launchctl_labels(fresh=True) if item.get('label')}
        except Exception:
            self._launchd_baseline = {}
        try:
            activity = self.scan_service.collect_network_activity()
            self._connection_baseline = {item.get('connection_key') or self._conn_key(item): item for item in (activity.get('connections') or [])}
        except Exception:
            self._connection_baseline = {}
        self._file_baseline = self._build_file_snapshot()

    def _run(self) -> None:
        try:
            while not self._stop_event.is_set():
                current_processes = {item['pid']: item for item in self.collector.collect_processes(fresh=True)}
                current_launchd = {item['label']: item for item in self.collector.collect_launchctl_labels(fresh=True) if item.get('label')}
                activity = self.scan_service.collect_network_activity()
                current_connections = {item.get('connection_key') or self._conn_key(item): item for item in (activity.get('connections') or [])}
                current_files = self._build_file_snapshot()
                pending: List[Dict] = []

                for finding in activity.get('findings') or []:
                    converted = self._convert_rule_finding(finding)
                    if converted:
                        pending.append(converted)

                new_pids = sorted(pid for pid in current_processes if pid not in self._process_baseline)
                for pid in new_pids[:36]:
                    pending.extend(self._inspect_new_process(current_processes[pid]))

                new_labels = sorted(label for label in current_launchd if label not in self._launchd_baseline)
                for label in new_labels[:20]:
                    pending.extend(self._inspect_new_launchd_label(label, current_launchd[label], current_files))

                changed_files = self._changed_files(current_files)
                for path in changed_files[:48]:
                    pending.extend(self._inspect_changed_file(path))

                new_connection_keys = [key for key in current_connections if key not in self._connection_baseline]
                for key in new_connection_keys[:36]:
                    pending.extend(self._inspect_connection(current_connections[key], current_processes))

                fresh = self._dedupe_recent(pending)
                if fresh:
                    self.state_store.append_protection_events(fresh)
                    for item in fresh:
                        location = item.get('matched_path') or item.get('launchd_label') or item.get('remote_address') or item.get('process_cmdline') or 'local host'
                        self.state_store.append_protection_log(
                            f"Detected {item.get('title', 'suspicious activity')} at {location}.",
                            level='warning',
                            phase='detect',
                            extra={'finding_id': item.get('finding_id', '')},
                        )
                        if self._should_auto_respond(item):
                            actions = self.remediation.active_respond(item)
                            quarantined = sum(1 for action in actions if 'Quarantined locally:' in action)
                            blocked = 1 if any(action.startswith('Sent SIG') or action.startswith('Attempted launchctl remove') or action.startswith('Quarantined locally:') for action in actions) else 0
                            self.state_store.record_protection_actions(blocked_delta=blocked, quarantined_delta=quarantined)
                            self.state_store.append_protection_log(
                                ' · '.join(actions),
                                level='warning',
                                phase='response',
                                extra={'finding_id': item.get('finding_id', '')},
                            )

                self.state_store.update_protection_cycle(observed_events=len(fresh))
                self._process_baseline = current_processes
                self._launchd_baseline = current_launchd
                self._connection_baseline = current_connections
                self._file_baseline = current_files
                self._expire_caches()
                self._stop_event.wait(self.interval_seconds)
        except Exception as exc:
            self.state_store.fail_protection(str(exc))
        finally:
            self.state_store.set_protection_running(False)
            self.state_store.append_protection_log('Active protection stopped.', phase='stop')

    def _expire_caches(self) -> None:
        now = time.time()
        self._recent_event_keys = {key: ts for key, ts in self._recent_event_keys.items() if now - ts < 180}
        self._recent_file_hits = {key: ts for key, ts in self._recent_file_hits.items() if now - ts < 180}
        self._recent_proc_hits = {key: ts for key, ts in self._recent_proc_hits.items() if now - ts < 180}

    def _existing_watch_paths(self) -> List[Path]:
        paths: List[Path] = []
        for raw in self._config.get('watch_paths', []) or []:
            expanded = Path(os.path.expanduser(str(raw))).resolve()
            if expanded.exists():
                paths.append(expanded)
        return paths

    def _build_file_snapshot(self) -> Dict[str, Dict]:
        snapshot: Dict[str, Dict] = {}
        for root in self._existing_watch_paths():
            max_depth = 3 if 'Downloads' in str(root) or 'Desktop' in str(root) else 2
            count = 0
            for path in self._iter_files(root, max_depth=max_depth):
                count += 1
                if count > 450:
                    break
                try:
                    stat = path.stat()
                except Exception:
                    continue
                snapshot[str(path)] = {
                    'mtime_ns': int(getattr(stat, 'st_mtime_ns', int(stat.st_mtime * 1_000_000_000))),
                    'size': int(stat.st_size),
                }
        return snapshot

    def _iter_files(self, root: Path, max_depth: int = 2):
        try:
            root_depth = len(root.parts)
            for current_root, dirs, files in os.walk(root):
                current_path = Path(current_root)
                depth = len(current_path.parts) - root_depth
                if depth >= max_depth:
                    dirs[:] = []
                dirs[:] = [name for name in dirs if name not in {'node_modules', '.git', '.Trash', '__pycache__'}]
                for name in files:
                    candidate = current_path / name
                    if self._is_candidate_file(candidate):
                        yield candidate
        except Exception:
            return

    def _is_candidate_file(self, path: Path) -> bool:
        if path.name.startswith('.') and path.suffix.lower() not in {'.plist', '.sh', '.py', '.js'}:
            return False
        suffix = path.suffix.lower()
        path_lower = str(path).lower()
        if '/library/launchagents/' in path_lower or '/library/launchdaemons/' in path_lower:
            return suffix == '.plist'
        if suffix in self.SUSPICIOUS_EXTENSIONS:
            return True
        try:
            return path.is_file() and os.access(path, os.X_OK)
        except Exception:
            return False

    def _changed_files(self, current: Dict[str, Dict]) -> List[str]:
        changed: List[str] = []
        for path, meta in current.items():
            prev = self._file_baseline.get(path)
            if not prev or prev.get('mtime_ns') != meta.get('mtime_ns') or prev.get('size') != meta.get('size'):
                changed.append(path)
        return sorted(changed)

    def _convert_rule_finding(self, finding: Dict) -> Optional[Dict]:
        if str(finding.get('source', 'live')) not in {'live', 'scan', 'protect'}:
            return None
        copied = dict(finding)
        copied['source'] = 'protect'
        copied['confidence'] = copied.get('confidence') or 'context'
        if copied.get('threat_level') == 'high' and copied.get('evidence_type') == 'network' and not copied.get('matched_pid') and not copied.get('matched_path'):
            return None
        return copied

    def _inspect_new_process(self, proc: Dict) -> List[Dict]:
        pid = int(proc.get('pid') or 0)
        comm = str(proc.get('comm', '') or '')
        cmdline = str(proc.get('args', '') or '')
        exec_path = self._extract_exec_path(cmdline)
        score = 0
        reasons: List[str] = []
        if exec_path and self._is_user_writable_path(exec_path):
            score += 35
            reasons.append('user-writable execution path')
        if self.SUSPICIOUS_CMD.search(cmdline):
            score += 25
            reasons.append('suspicious commandline')
        if comm in {'osascript', 'bash', 'sh', 'python', 'perl', 'ruby'} and self._references_watched_drop_zone(cmdline):
            score += 20
            reasons.append('interpreter launched from recent drop zone')
        if exec_path and exec_path in self._recent_file_hits and time.time() - self._recent_file_hits[exec_path] < 150:
            score += 20
            reasons.append('new executable followed a file drop')
        if score < 60:
            return []
        self._recent_proc_hits[pid] = time.time()
        title = 'Active protection: suspicious process launch'
        threat_level = 'high' if score >= 75 else 'mid'
        return [self._make_finding(
            rule_id='active_process_behavior',
            title=title,
            threat_level=threat_level,
            description='A newly observed process launched from a risky location or used an unusually suspicious command line. This was detected locally by the active-protection behavior layer.',
            evidence_type='process',
            matched_path=exec_path,
            matched_pid=pid,
            process_name=comm,
            process_cmdline=cmdline,
            matched_regex='; '.join(reasons),
            confidence='high' if score >= 75 else 'context',
        )]

    def _inspect_new_launchd_label(self, label: str, entry: Dict, current_files: Dict[str, Dict]) -> List[Dict]:
        label_l = label.lower()
        if not label_l:
            return []
        related_paths = [path for path in current_files if path.lower().endswith('.plist') and any(seg in path.lower() for seg in self.PERSISTENCE_SEGMENTS)]
        findings: List[Dict] = []
        for path in related_paths[:24]:
            plist = self.collector.parse_plist(path)
            if str(plist.get('Label', '')).strip() != label:
                continue
            findings.extend(self._inspect_changed_file(path))
            if findings:
                return findings
        score = 20 if re.search(r'\b(update|helper|agent|daemon)\b', label_l) else 0
        if score < 20:
            return []
        return [self._make_finding(
            rule_id='active_launchd_label',
            title='Active protection: new launchd label observed',
            threat_level='low',
            description='A new launchd label appeared during active monitoring. This is a weak signal by itself but can matter when combined with file or network activity.',
            evidence_type='launchd',
            launchd_label=label,
            matched_regex='new launchd label',
            confidence='context',
        )]

    def _inspect_changed_file(self, path: str) -> List[Dict]:
        target = Path(path)
        if not target.exists() or not target.is_file():
            return []
        path_l = str(target).lower()
        suffix = target.suffix.lower()
        score = 0
        reasons: List[str] = []
        text = self.collector.read_text(str(target), 160 * 1024, skip_binary=False) or ''
        if self._is_user_writable_path(str(target)):
            score += 15
            reasons.append('user-writable drop zone')
        if suffix in self.SUSPICIOUS_EXTENSIONS:
            score += 15
            reasons.append(f'{suffix or "executable"} file type')
        if self.SUSPICIOUS_CMD.search(text):
            score += 25
            reasons.append('suspicious script contents')
        if any(seg in path_l for seg in self.PERSISTENCE_SEGMENTS) and suffix == '.plist':
            score += 35
            reasons.append('launchd persistence path')
            plist = self.collector.parse_plist(str(target))
            program = str(plist.get('Program', '') or '')
            args = ' '.join(plist.get('ProgramArguments', []) or [])
            if self._is_user_writable_path(program) or self._references_watched_drop_zone(args):
                score += 45
                reasons.append('launchd target from user-writable path')
            if self.SUSPICIOUS_CMD.search(args):
                score += 25
                reasons.append('launchd args contain suspicious command')
        if self._has_quarantine_xattr(target):
            score += 5
            reasons.append('download quarantine xattr present')
        try:
            if os.access(target, os.X_OK):
                score += 10
                reasons.append('executable bit set')
        except Exception:
            pass
        if score < 55:
            return []
        self._recent_file_hits[str(target)] = time.time()
        title = 'Active protection: suspicious file drop'
        description = 'A newly created or modified file in a sensitive or user-writable path matched local suspicious-content and persistence heuristics.'
        if any(seg in path_l for seg in self.PERSISTENCE_SEGMENTS):
            title = 'Active protection: suspicious persistence item'
            description = 'A new or changed launchd persistence file referenced a risky user-writable path or suspicious command sequence.'
        threat_level = 'high' if score >= 80 else 'mid'
        launchd_label = ''
        if suffix == '.plist':
            try:
                launchd_label = str(self.collector.parse_plist(str(target)).get('Label', '') or '')
            except Exception:
                launchd_label = ''
        return [self._make_finding(
            rule_id='active_file_drop' if 'persistence' not in title.lower() else 'active_persistence_item',
            title=title,
            threat_level=threat_level,
            description=description,
            evidence_type='file',
            matched_path=str(target),
            launchd_label=launchd_label,
            matched_regex='; '.join(reasons),
            confidence='high' if score >= 80 else 'context',
        )]

    def _inspect_connection(self, conn: Dict, processes: Dict[int, Dict]) -> List[Dict]:
        pid = int(conn.get('pid') or 0)
        proc = processes.get(pid, {})
        cmdline = str(proc.get('args', '') or conn.get('process_cmdline', '') or '')
        process_name = str(proc.get('comm', '') or conn.get('process_name', '') or conn.get('command', '') or '')
        exec_path = self._extract_exec_path(cmdline)
        remote_port = conn.get('remote_port')
        remote_address = str(conn.get('remote_address', '') or '')
        score = 0
        reasons: List[str] = []
        if remote_port in self.SUSPICIOUS_PORTS:
            score += 25
            reasons.append(f'suspicious remote port {remote_port}')
        if self.SUSPICIOUS_CMD.search(cmdline):
            score += 20
            reasons.append('suspicious commandline')
        if exec_path and self._is_user_writable_path(exec_path):
            score += 35
            reasons.append('networking process from user-writable path')
        if pid in self._recent_proc_hits and time.time() - self._recent_proc_hits[pid] < 150:
            score += 15
            reasons.append('followed suspicious process launch')
        if remote_port and int(remote_port) not in self.COMMON_PORTS and not conn.get('service_guess'):
            score += 10
            reasons.append('uncommon outbound service')
        if not remote_address or remote_address in {'127.0.0.1', '::1', 'localhost'}:
            return []
        if score < 60:
            return []
        return [self._make_finding(
            rule_id='active_network_behavior',
            title='Active protection: suspicious outbound network behavior',
            threat_level='high' if score >= 75 else 'mid',
            description='A newly observed outbound connection correlated with risky process behavior or a user-writable execution path.',
            evidence_type='network',
            matched_path=exec_path,
            matched_pid=pid or None,
            process_name=process_name,
            process_cmdline=cmdline,
            remote_address=remote_address,
            remote_port=remote_port,
            protocol=str(conn.get('protocol', '') or ''),
            matched_regex='; '.join(reasons),
            confidence='high' if score >= 75 else 'context',
        )]

    def _dedupe_recent(self, findings: List[Dict]) -> List[Dict]:
        now = time.time()
        fresh: List[Dict] = []
        for item in findings:
            key = (
                item.get('rule_id'),
                item.get('evidence_type'),
                item.get('matched_path'),
                item.get('matched_pid'),
                item.get('launchd_label'),
                item.get('remote_address'),
                item.get('remote_port'),
            )
            last_seen = self._recent_event_keys.get(key, 0.0)
            if now - last_seen < 90:
                continue
            self._recent_event_keys[key] = now
            fresh.append(item)
        return fresh

    def _should_auto_respond(self, finding: Dict) -> bool:
        if not self._config.get('enabled'):
            return False
        if str(self._config.get('mode', 'protect')) != 'protect':
            return False
        if finding.get('threat_level') not in {'high'} and finding.get('confidence') != 'high':
            return False
        if finding.get('matched_path') and self.remediation.is_protected_path(str(finding.get('matched_path'))):
            return False
        return bool(finding.get('matched_path') or finding.get('matched_pid') or finding.get('launchd_label'))

    def _make_finding(self, **kwargs) -> Dict:
        finding = Finding(
            family='Active Protection',
            author_or_actor='Mac Sentinel',
            source='protect',
            **kwargs,
        )
        return finding.to_dict()

    def _extract_exec_path(self, cmdline: str) -> str:
        command = str(cmdline or '').strip()
        if not command:
            return ''
        first = command.split(' ', 1)[0].strip().strip('"\'')
        return first if first.startswith('/') else ''

    def _is_user_writable_path(self, path: str) -> bool:
        path_l = str(path or '').lower()
        return any(segment in path_l for segment in self.USER_WRITABLE_SEGMENTS)

    def _references_watched_drop_zone(self, value: str) -> bool:
        return self._is_user_writable_path(value)

    def _has_quarantine_xattr(self, target: Path) -> bool:
        try:
            return 'com.apple.quarantine' in set(os.listxattr(target))
        except Exception:
            return False

    def _conn_key(self, conn: Dict) -> str:
        return '|'.join(str(part) for part in (
            conn.get('pid') or 0,
            conn.get('protocol') or '',
            conn.get('local_address') or '',
            conn.get('local_port') or 0,
            conn.get('remote_address') or '',
            conn.get('remote_port') or 0,
        ))
