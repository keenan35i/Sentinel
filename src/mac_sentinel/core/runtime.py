from __future__ import annotations

import fnmatch
import glob
import json
import os
import plistlib
import re
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

from ..config import settings
from .content_filters import is_probably_binary


class ScanStopRequested(Exception):
    pass


class PatternEnumerationTimeout(Exception):
    pass


class RuntimeCollector:
    def __init__(self):
        self.clear()
        self._should_pause: Callable[[], bool] = lambda: False
        self._should_stop: Callable[[], bool] = lambda: False

    def configure_controls(self, should_pause: Callable[[], bool], should_stop: Callable[[], bool]) -> None:
        self._should_pause = should_pause
        self._should_stop = should_stop

    def _cooperate(self) -> None:
        while self._should_pause():
            time.sleep(0.15)
        if self._should_stop():
            raise ScanStopRequested('Scan stop requested by user.')

    def clear(self) -> None:
        self._glob_cache: Dict[str, List[str]] = {}
        self._text_cache: Dict[str, str] = {}
        self._plist_cache: Dict[str, Dict] = {}
        self._process_cache: Optional[List[Dict]] = None
        self._launchctl_cache: Optional[List[Dict]] = None
        self._network_cache: Optional[List[Dict]] = None

    def expand_pattern(self, pattern: str) -> str:
        return os.path.expandvars(os.path.expanduser(pattern))

    def glob_paths(self, pattern: str) -> List[str]:
        expanded = self.expand_pattern(pattern)
        if expanded in self._glob_cache:
            return self._glob_cache[expanded]

        self._cooperate()
        if '**' in expanded:
            matches = self._bounded_recursive_matches(expanded)
        elif any(token in expanded for token in ('*', '?', '[')):
            matches = sorted(set(glob.glob(expanded, recursive=False)))[: settings.max_recursive_matches_per_pattern]
        else:
            matches = [expanded] if os.path.exists(expanded) else []
        self._glob_cache[expanded] = matches
        return matches

    def _bounded_recursive_matches(self, expanded_pattern: str) -> List[str]:
        prefix, _ = expanded_pattern.split('**', 1)
        root = prefix.rstrip('/') or '/'
        if not os.path.exists(root):
            return []

        deadline = time.time() + settings.recursive_pattern_timeout_seconds
        results: List[str] = []

        for current_root, dirs, files in os.walk(root):
            self._cooperate()
            if time.time() > deadline:
                raise PatternEnumerationTimeout(
                    f'Pattern walk timed out after {settings.recursive_pattern_timeout_seconds}s: {expanded_pattern}'
                )

            dirs[:] = [
                name for name in dirs
                if name not in {'node_modules', '.git', '.Trash', 'Cache', 'Caches', '__pycache__', '.venv'}
            ]

            for name in dirs + files:
                self._cooperate()
                candidate = os.path.join(current_root, name)
                if fnmatch.fnmatch(candidate, expanded_pattern):
                    results.append(candidate)
                    if len(results) >= settings.max_recursive_matches_per_pattern:
                        return sorted(set(results))
        return sorted(set(results))

    def read_text(self, path: str, max_bytes: int, skip_binary: bool = True) -> str:
        self._cooperate()
        cache_key = f'{path}:{max_bytes}:{skip_binary}'
        if cache_key in self._text_cache:
            return self._text_cache[cache_key]
        target = Path(path)
        if not target.exists() or not target.is_file():
            self._text_cache[cache_key] = ''
            return ''
        try:
            if target.stat().st_size > max_bytes:
                self._text_cache[cache_key] = ''
                return ''
            with target.open('rb') as handle:
                data = handle.read(max_bytes)
            if skip_binary and is_probably_binary(data):
                self._text_cache[cache_key] = ''
                return ''
            text = data.decode('utf-8', errors='ignore')
        except Exception:
            text = ''
        self._text_cache[cache_key] = text
        return text

    def parse_plist(self, path: str) -> Dict:
        self._cooperate()
        if path in self._plist_cache:
            return self._plist_cache[path]
        payload = {'Label': '', 'Program': '', 'ProgramArguments': []}
        target = Path(path)
        if not target.exists() or not target.is_file():
            self._plist_cache[path] = payload
            return payload
        try:
            with target.open('rb') as handle:
                obj = plistlib.load(handle)
            payload['Label'] = str(obj.get('Label', ''))
            payload['Program'] = str(obj.get('Program', ''))
            payload['ProgramArguments'] = [str(x) for x in (obj.get('ProgramArguments', []) or []) if x is not None]
        except Exception:
            text = self.read_text(path, 1024 * 1024, skip_binary=False)
            label = re.search(r'<key>\s*Label\s*</key>\s*<string>(.*?)</string>', text, re.I | re.S)
            program = re.search(r'<key>\s*Program\s*</key>\s*<string>(.*?)</string>', text, re.I | re.S)
            blocks = re.findall(r'<key>\s*ProgramArguments\s*</key>.*?<array>(.*?)</array>', text, re.I | re.S)
            args = []
            for block in blocks:
                args.extend(re.findall(r'<string>(.*?)</string>', block, re.I | re.S))
            payload['Label'] = label.group(1).strip() if label else ''
            payload['Program'] = program.group(1).strip() if program else ''
            payload['ProgramArguments'] = [item.strip() for item in args]
        self._plist_cache[path] = payload
        return payload

    def run_command(self, command: List[str], timeout: int = 10) -> str:
        self._cooperate()
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
            return (result.stdout or '') + ('\n' + result.stderr if result.stderr else '')
        except Exception:
            return ''

    def run_command_bytes(self, command: List[str], timeout: int = 10) -> bytes:
        self._cooperate()
        try:
            result = subprocess.run(command, capture_output=True, timeout=timeout)
            stderr = result.stderr or b''
            return (result.stdout or b'') + ((b'\n' + stderr) if stderr else b'')
        except Exception:
            return b''

    def collect_processes(self, fresh: bool = False) -> List[Dict]:
        self._cooperate()
        if self._process_cache is not None and not fresh:
            return self._process_cache
        output = self.run_command(['ps', '-axo', 'pid=,user=,comm=,args='], timeout=12)
        rows = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = re.split(r'\s+', line, maxsplit=3)
            if len(parts) < 4:
                continue
            pid_s, user, comm, args = parts
            try:
                pid = int(pid_s)
            except ValueError:
                continue
            rows.append({'pid': pid, 'user': user, 'comm': comm, 'args': args})
        self._process_cache = rows
        return rows

    def collect_launchctl_labels(self, fresh: bool = False) -> List[Dict]:
        self._cooperate()
        if self._launchctl_cache is not None and not fresh:
            return self._launchctl_cache
        output = self.run_command(['launchctl', 'list'], timeout=12)
        rows = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith('PID'):
                continue
            parts = re.split(r'\s+', line, maxsplit=2)
            if len(parts) < 3:
                continue
            pid_s, status_s, label = parts
            try:
                pid = None if pid_s == '-' else int(pid_s)
            except ValueError:
                pid = None
            rows.append({'pid': pid, 'status': status_s, 'label': label})
        self._launchctl_cache = rows
        return rows

    def collect_network_connections(self, fresh: bool = False) -> List[Dict]:
        self._cooperate()
        if self._network_cache is not None and not fresh:
            return self._network_cache
        output = self.run_command(['lsof', '-nP', '-i'], timeout=12)
        rows = []
        for line in output.splitlines():
            if not line.strip() or line.startswith('COMMAND'):
                continue
            parts = re.split(r'\s+', line.strip(), maxsplit=8)
            if len(parts) < 9:
                continue
            command, pid_s, user, fd, ftype, device, size_off, node, name = parts
            try:
                pid = int(pid_s)
            except ValueError:
                continue
            clean_name = re.sub(r'\s+\([A-Z_]+\)$', '', name).strip()
            state_match = re.search(r'\(([A-Z_]+)\)\s*$', name)
            state = state_match.group(1) if state_match else ('ESTABLISHED' if node.upper() == 'TCP' and '->' in clean_name else '')
            local_host, local_port, remote_host, remote_port = self._parse_pair(name)
            rows.append({
                'command': command,
                'pid': pid,
                'user': user,
                'fd': fd,
                'protocol': node.upper(),
                'transport': node.upper(),
                'state': state,
                'name': clean_name,
                'raw_name': name,
                'local_address': local_host,
                'local_port': local_port,
                'remote_address': remote_host,
                'remote_port': remote_port,
                'is_loopback': local_host in {'127.0.0.1', '::1', 'localhost'} or remote_host in {'127.0.0.1', '::1', 'localhost'},
                'service_guess': self._guess_service(remote_port or local_port),
                'connection_key': '|'.join(str(part) for part in (pid, fd, node.upper(), local_host, local_port or 0, remote_host, remote_port or 0)),
            })
        self._network_cache = rows
        return rows

    def _parse_pair(self, raw_name: str):
        name = re.sub(r'\s+\([A-Z_]+\)$', '', raw_name).strip()
        if '->' in name:
            left, right = name.split('->', 1)
        else:
            left, right = name, ''
        local_address, local_port = self._split_host_port(left)
        remote_address, remote_port = self._split_host_port(right) if right else ('', None)
        return local_address, local_port, remote_address, remote_port

    def _guess_service(self, port: Optional[int]) -> str:
        common = {
            22: 'SSH', 53: 'DNS', 80: 'HTTP', 123: 'NTP', 135: 'RPC', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'SMB',
            389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 500: 'IPsec', 587: 'SMTP Submission',
            631: 'IPP', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle DB', 2049: 'NFS',
            2375: 'Docker', 2376: 'Docker TLS', 3000: 'Dev HTTP', 3306: 'MySQL', 3389: 'RDP', 5000: 'Dev App',
            5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 6443: 'Kubernetes API', 8000: 'Dev HTTP',
            8080: 'HTTP Alt', 8443: 'HTTPS Alt', 9000: 'Dev API', 9200: 'Elasticsearch', 11434: 'Ollama'
        }
        return common.get(int(port), '') if port is not None else ''

    def _split_host_port(self, value: str):
        value = value.strip()
        if not value:
            return '', None
        if value.startswith('[') and ']:' in value:
            host, port = value.rsplit(']:', 1)
            host = host.strip('[]')
            try:
                return host, int(port)
            except ValueError:
                return host, None
        if ':' in value:
            host, port = value.rsplit(':', 1)
            try:
                return host, int(port)
            except ValueError:
                return host, None
        return value, None


    def collect_unified_logs_json(self, last_minutes: int = 90, predicate: str = '') -> List[Dict]:
        self._cooperate()
        minutes = max(5, min(int(last_minutes or 90), 24 * 60))
        command = ['log', 'show', '--style', 'json', '--last', f'{minutes}m']
        if predicate:
            command.extend(['--predicate', predicate])
        payload = self.run_command(command, timeout=40)
        rows: List[Dict] = []
        for line in payload.splitlines():
            line = line.strip()
            if not line or not line.startswith('{'):
                continue
            try:
                item = json.loads(line)
            except Exception:
                continue
            if isinstance(item, dict):
                rows.append(item)
                if len(rows) >= 5000:
                    break
        return rows

    def collect_installed_profiles(self) -> List[Dict]:
        commands = [
            ['profiles', 'show', '-type', 'configuration', '-output', 'stdout-xml'],
            ['profiles', '-P', '-o', 'stdout-xml'],
        ]
        payload = b''
        for command in commands:
            payload = self.run_command_bytes(command, timeout=18)
            if payload and b'PayloadIdentifier' in payload:
                break

        if not payload:
            return []

        try:
            obj = plistlib.loads(payload)
        except Exception:
            try:
                text = payload.decode('utf-8', errors='ignore')
            except Exception:
                return []
            return self._parse_profiles_from_text(text)

        profiles: List[Dict] = []
        self._extract_profile_dicts(obj, profiles)
        return profiles

    def _extract_profile_dicts(self, obj, profiles: List[Dict]) -> None:
        if isinstance(obj, list):
            for item in obj:
                self._extract_profile_dicts(item, profiles)
            return

        if not isinstance(obj, dict):
            return

        if 'PayloadIdentifier' in obj and ('PayloadContent' in obj or obj.get('PayloadType') == 'Configuration'):
            payload_content = obj.get('PayloadContent', []) or []
            payload_types = []
            if isinstance(payload_content, list):
                for entry in payload_content:
                    if isinstance(entry, dict) and entry.get('PayloadType'):
                        payload_types.append(str(entry.get('PayloadType')))
            if not payload_types and obj.get('PayloadType'):
                payload_types.append(str(obj.get('PayloadType')))
            profiles.append({
                'identifier': str(obj.get('PayloadIdentifier', '')),
                'display_name': str(obj.get('PayloadDisplayName', obj.get('ProfileDisplayName', ''))),
                'organization': str(obj.get('PayloadOrganization', obj.get('ProfileOrganization', ''))),
                'uuid': str(obj.get('PayloadUUID', '')),
                'payload_types': sorted(set(payload_types)),
                'removal_disallowed': bool(obj.get('PayloadRemovalDisallowed', False)),
                'payload_text': json.dumps(payload_content or obj, sort_keys=True, ensure_ascii=False),
            })
            return

        for value in obj.values():
            self._extract_profile_dicts(value, profiles)

    def _parse_profiles_from_text(self, text: str) -> List[Dict]:
        if 'PayloadIdentifier' not in text:
            return []
        chunks = re.split(r'(?=PayloadIdentifier)', text)
        profiles = []
        for chunk in chunks:
            identifier = re.search(r'PayloadIdentifier[^A-Za-z0-9._-]*([A-Za-z0-9._-]+)', chunk)
            if not identifier:
                continue
            display = re.search(r'PayloadDisplayName[^\n:]*[:=]\s*(.+)', chunk)
            organization = re.search(r'PayloadOrganization[^\n:]*[:=]\s*(.+)', chunk)
            payload_types = re.findall(r'com\.apple\.[A-Za-z0-9._-]+', chunk)
            profiles.append({
                'identifier': identifier.group(1).strip(),
                'display_name': display.group(1).strip() if display else identifier.group(1).strip(),
                'organization': organization.group(1).strip() if organization else '',
                'uuid': '',
                'payload_types': sorted(set(payload_types)),
                'removal_disallowed': 'PayloadRemovalDisallowed = 1' in chunk,
                'payload_text': chunk,
            })
        return profiles

    def collect_tcc_entries(self) -> List[Dict]:
        entries: List[Dict] = []
        db_paths = [
            self.expand_pattern('~/Library/Application Support/com.apple.TCC/TCC.db'),
            '/Library/Application Support/com.apple.TCC/TCC.db',
        ]

        for db_path in db_paths:
            if not os.path.exists(db_path) or not os.access(db_path, os.R_OK):
                continue
            try:
                conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
                conn.row_factory = sqlite3.Row
                columns = [row['name'] for row in conn.execute('PRAGMA table_info(access)')]
                wanted = [name for name in ('service', 'client', 'client_type', 'auth_value', 'allowed', 'prompt_count', 'indirect_object_identifier') if name in columns]
                if not wanted:
                    conn.close()
                    continue
                query = f"SELECT {', '.join(wanted)} FROM access"
                for row in conn.execute(query):
                    item = {name: row[name] for name in wanted}
                    auth_value = item.get('auth_value')
                    allowed = item.get('allowed')
                    item['allowed'] = bool(allowed) if allowed is not None else auth_value in {1, 2, 3}
                    item['db_path'] = db_path
                    entries.append(item)
                conn.close()
            except Exception:
                continue
        return entries

    def collect_diagnostic_reports(self, days: int = 7, limit: int = 200) -> List[Dict]:
        now = time.time()
        roots = [
            self.expand_pattern('~/Library/Logs/DiagnosticReports'),
            '/Library/Logs/DiagnosticReports',
        ]
        interesting = ('messagesblastdoorservice', 'imagent', 'identityservicesd', 'webkit')
        rows: List[Dict] = []
        for root in roots:
            if not os.path.isdir(root):
                continue
            try:
                names = sorted(os.listdir(root), reverse=True)
            except Exception:
                continue
            for name in names:
                lowered = name.lower()
                if not lowered.endswith(('.ips', '.crash')):
                    continue
                if not any(token in lowered for token in interesting):
                    continue
                path = os.path.join(root, name)
                try:
                    mtime = os.path.getmtime(path)
                except OSError:
                    continue
                if now - mtime > days * 86400:
                    continue
                process = name.split('_', 1)[0]
                rows.append({
                    'process': process,
                    'path': path,
                    'mtime': mtime,
                })
                if len(rows) >= limit:
                    return rows
        return rows


    def collect_recent_downloaded_candidates(self, days: int = 30, limit: int = 120) -> List[Dict]:
        now = time.time()
        roots = [
            self.expand_pattern('~/Downloads'),
            self.expand_pattern('~/Desktop'),
        ]
        interesting_suffixes = {'.app', '.pkg', '.dmg', '.command', '.sh', '.py', '.js'}
        rows: List[Dict] = []
        for root in roots:
            if not os.path.isdir(root):
                continue
            for current_root, dirs, files in os.walk(root):
                self._cooperate()
                dirs[:] = [name for name in dirs if name not in {'node_modules', '.git', '__pycache__', '.venv'}]
                for name in files:
                    path = os.path.join(current_root, name)
                    try:
                        stat = os.stat(path)
                    except OSError:
                        continue
                    if now - stat.st_mtime > days * 86400:
                        continue
                    suffix = Path(path).suffix.lower()
                    executable = bool(stat.st_mode & 0o111)
                    if suffix not in interesting_suffixes and not executable:
                        continue
                    rows.append({
                        'path': path,
                        'mtime': stat.st_mtime,
                        'size': stat.st_size,
                        'suffix': suffix,
                        'executable': executable,
                    })
                    if len(rows) >= limit:
                        return rows
        return rows

    def collect_file_security_metadata(self, path: str) -> Dict:
        metadata = {
            'path': path,
            'quarantine': '',
            'has_quarantine': False,
            'where_froms': [],
            'origin_url': '',
            'codesign_authority': '',
            'team_id': '',
            'identifier': '',
            'signature_type': '',
            'designated_requirement': '',
            'runtime_flags': '',
            'spctl_assessment': '',
            'spctl_accepted': False,
            'spctl_source': '',
            'notarized': False,
        }
        quarantine = self.run_command(['xattr', '-p', 'com.apple.quarantine', path], timeout=8).strip()
        if quarantine:
            metadata['quarantine'] = quarantine
            metadata['has_quarantine'] = True

        where_froms_raw = self.run_command(['xattr', '-p', 'com.apple.metadata:kMDItemWhereFroms', path], timeout=8)
        if where_froms_raw:
            urls = re.findall(r"https?://[^\s,\"']+", where_froms_raw)
            metadata['where_froms'] = urls
            metadata['origin_url'] = urls[0] if urls else ''

        code_output = self.run_command(['codesign', '-dv', '--verbose=4', path], timeout=12)
        if code_output:
            auth_match = re.search(r'Authority=(.+)', code_output)
            team_match = re.search(r'TeamIdentifier=(.+)', code_output)
            ident_match = re.search(r'Identifier=(.+)', code_output)
            flag_match = re.search(r'flags=.+?\((.+?)\)', code_output)
            req_match = re.search(r'Designated =>\s*(.+)', code_output)
            runtime_match = re.search(r'Runtime Version=(.+)', code_output)
            if auth_match:
                metadata['codesign_authority'] = auth_match.group(1).strip()
            if team_match:
                metadata['team_id'] = team_match.group(1).strip()
            if ident_match:
                metadata['identifier'] = ident_match.group(1).strip()
            if flag_match:
                metadata['signature_type'] = flag_match.group(1).strip()
            if req_match:
                metadata['designated_requirement'] = req_match.group(1).strip()
            if runtime_match:
                metadata['runtime_flags'] = runtime_match.group(1).strip()
            if 'code object is not signed at all' in code_output.lower():
                metadata['signature_type'] = 'unsigned'

        spctl_output = self.run_command(['spctl', '-a', '-vv', path], timeout=12).strip()
        if spctl_output:
            metadata['spctl_assessment'] = spctl_output
            lowered = spctl_output.lower()
            metadata['spctl_accepted'] = 'accepted' in lowered
            metadata['notarized'] = 'notarized' in lowered
            source_match = re.search(r'source=(.+)', spctl_output, re.I)
            if source_match:
                metadata['spctl_source'] = source_match.group(1).strip()
        return metadata

    def collect_user_trust_settings(self) -> Dict:
        outputs = {
            'admin': self.run_command(['security', 'dump-trust-settings', '-d'], timeout=15),
            'user': self.run_command(['security', 'dump-trust-settings'], timeout=15),
        }
        summary = {'admin_has_custom_settings': False, 'user_has_custom_settings': False, 'raw': outputs}
        for key, value in outputs.items():
            lowered = (value or '').lower()
            has_custom = 'no trust settings were found' not in lowered and bool(value.strip())
            if key == 'admin':
                summary['admin_has_custom_settings'] = has_custom
            else:
                summary['user_has_custom_settings'] = has_custom
        return summary


    def collect_browser_extensions(self, limit: int = 120) -> List[Dict]:
        roots = [
            ('Chrome', self.expand_pattern('~/Library/Application Support/Google/Chrome')),
            ('Brave', self.expand_pattern('~/Library/Application Support/BraveSoftware/Brave-Browser')),
            ('Edge', self.expand_pattern('~/Library/Application Support/Microsoft Edge')),
        ]
        rows: List[Dict] = []
        for browser_name, root in roots:
            if not os.path.isdir(root):
                continue
            try:
                profiles = [name for name in os.listdir(root) if name == 'Default' or name.startswith('Profile ')]
            except Exception:
                continue
            for profile in profiles:
                ext_root = os.path.join(root, profile, 'Extensions')
                if not os.path.isdir(ext_root):
                    continue
                for extension_id in os.listdir(ext_root):
                    version_root = os.path.join(ext_root, extension_id)
                    if not os.path.isdir(version_root):
                        continue
                    versions = sorted(os.listdir(version_root), reverse=True)
                    if not versions:
                        continue
                    manifest_path = os.path.join(version_root, versions[0], 'manifest.json')
                    manifest_text = self.read_text(manifest_path, 512 * 1024, skip_binary=True)
                    if not manifest_text:
                        continue
                    try:
                        manifest = json.loads(manifest_text)
                    except Exception:
                        continue
                    permissions = manifest.get('permissions', []) or []
                    host_permissions = manifest.get('host_permissions', []) or manifest.get('optional_host_permissions', []) or []
                    rows.append({
                        'browser': browser_name,
                        'profile': profile,
                        'extension_id': extension_id,
                        'manifest_path': manifest_path,
                        'name': str(manifest.get('name', extension_id)),
                        'version': str(manifest.get('version', '')),
                        'permissions': [str(item) for item in permissions],
                        'host_permissions': [str(item) for item in host_permissions],
                        'update_url': str(manifest.get('update_url', '')),
                        'manifest_version': manifest.get('manifest_version'),
                        'has_native_messaging': 'nativeMessaging' in permissions,
                        'is_unpacked': '__MSG_' not in str(manifest.get('name', '')) and not manifest.get('update_url'),
                    })
                    if len(rows) >= limit:
                        return rows
        return rows

    def collect_login_items(self, limit: int = 60) -> List[Dict]:
        output = self.run_command([
            'osascript', '-e',
            'tell application "System Events" to get the properties of every login item'
        ], timeout=12)
        rows: List[Dict] = []
        for chunk in output.split('login item '):
            path_match = re.search(r'path:([^,]+)', chunk)
            name_match = re.search(r'name:([^,]+)', chunk)
            hidden_match = re.search(r'hidden:(true|false)', chunk, re.I)
            if not path_match and not name_match:
                continue
            rows.append({
                'name': name_match.group(1).strip() if name_match else '',
                'path': path_match.group(1).strip() if path_match else '',
                'hidden': hidden_match.group(1).lower() == 'true' if hidden_match else False,
            })
            if len(rows) >= limit:
                break
        return rows

    def collect_background_items(self, limit: int = 120) -> List[Dict]:
        """
        Collect background-item style persistence candidates without invoking
        `sfltool dumpbtm`.

        On newer macOS versions, `sfltool dumpbtm` can trigger an interactive
        authorization prompt (the exact popup the user reported). For this app,
        avoiding that prompt is more important than getting Apple's full BTM
        view, so we stay in read-only userland and enumerate common persistence
        locations that do not require elevation.
        """
        rows: List[Dict] = []
        seen: set[str] = set()

        candidate_paths = [
            os.path.expanduser('~/Library/LaunchAgents'),
            '/Library/LaunchAgents',
            '/Library/LaunchDaemons',
        ]

        def _add_item(item: Dict) -> None:
            nonlocal rows
            path_value = str(item.get('path', '') or '')
            identifier = str(item.get('identifier', '') or '')
            dedupe_key = f'{identifier}|{path_value}'
            if dedupe_key in seen:
                return
            seen.add(dedupe_key)
            rows.append({
                'path': path_value,
                'identifier': identifier,
                'type': str(item.get('type', '') or 'background-item'),
                'team_identifier': str(item.get('team_identifier', '') or ''),
                'disposition': str(item.get('disposition', '') or 'filesystem-enumerated'),
            })

        for base in candidate_paths:
            self._cooperate()
            if not os.path.isdir(base):
                continue
            try:
                names = sorted(os.listdir(base))
            except Exception:
                continue

            for name in names:
                self._cooperate()
                if not name.endswith('.plist'):
                    continue
                plist_path = os.path.join(base, name)
                plist_data = self.read_plist(plist_path)
                label = str(plist_data.get('Label', '') or Path(plist_path).stem)

                program = ''
                if isinstance(plist_data.get('Program'), str):
                    program = str(plist_data.get('Program', ''))
                elif isinstance(plist_data.get('ProgramArguments'), list) and plist_data.get('ProgramArguments'):
                    first = plist_data['ProgramArguments'][0]
                    if isinstance(first, str):
                        program = first

                disposition_parts = ['plist']
                if base.startswith('/Library/LaunchDaemons'):
                    item_type = 'launch-daemon'
                    disposition_parts.append('system')
                elif base.startswith('/Library/LaunchAgents'):
                    item_type = 'launch-agent'
                    disposition_parts.append('global')
                else:
                    item_type = 'launch-agent'
                    disposition_parts.append('user')

                run_at_load = plist_data.get('RunAtLoad')
                keep_alive = plist_data.get('KeepAlive')
                if run_at_load:
                    disposition_parts.append('run-at-load')
                if keep_alive:
                    disposition_parts.append('keep-alive')

                _add_item({
                    'path': program or plist_path,
                    'identifier': label,
                    'type': item_type,
                    'team_identifier': '',
                    'disposition': ','.join(disposition_parts),
                })
                if len(rows) >= limit:
                    return rows

        # Best-effort enumeration of user login/startup helpers inside common app
        # locations without triggering macOS authorization prompts.
        login_item_roots = [
            os.path.expanduser('~/Applications'),
            '/Applications',
        ]
        for root in login_item_roots:
            self._cooperate()
            if not os.path.isdir(root):
                continue
            for app_path in glob.glob(os.path.join(root, '*.app')):
                self._cooperate()
                helper_glob = os.path.join(app_path, 'Contents', 'Library', 'LoginItems', '*.app')
                for helper_path in glob.glob(helper_glob):
                    self._cooperate()
                    helper_name = Path(helper_path).stem
                    _add_item({
                        'path': helper_path,
                        'identifier': helper_name,
                        'type': 'login-item-helper',
                        'team_identifier': '',
                        'disposition': 'bundle-login-item',
                    })
                    if len(rows) >= limit:
                        return rows

        return rows

    def collect_bundle_components(self, app_path: str, limit: int = 40) -> List[Dict]:
        rows: List[Dict] = []
        if not app_path.endswith('.app') or not os.path.isdir(app_path):
            return rows
        interesting_suffixes = {'.dylib', '.node', ''}
        for current_root, dirs, files in os.walk(app_path):
            self._cooperate()
            dirs[:] = [name for name in dirs if name not in {'Resources'}]
            for name in files:
                candidate = os.path.join(current_root, name)
                suffix = Path(candidate).suffix.lower()
                executable = os.access(candidate, os.X_OK)
                if not executable and suffix not in interesting_suffixes:
                    continue
                rows.append({
                    'path': candidate,
                    'metadata': self.collect_file_security_metadata(candidate),
                })
                if len(rows) >= limit:
                    return rows
        return rows
