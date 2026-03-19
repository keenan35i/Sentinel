from __future__ import annotations

import json
from pathlib import Path
from threading import RLock
from typing import Dict, List

from ..config import settings


class RuleRepository:
    def __init__(self, rules_path: Path):
        self.rules_path = Path(rules_path)
        self._lock = RLock()
        self._payload: Dict = {}
        self.reload()

    def reload(self) -> Dict:
        with self._lock:
            with self.rules_path.open('r', encoding='utf-8') as handle:
                payload = json.load(handle)
            if not isinstance(payload, dict) or 'rules' not in payload or not isinstance(payload['rules'], list):
                raise ValueError("Rules JSON must be an object with a top-level 'rules' array.")
            normalized = []
            for index, rule in enumerate(payload['rules'], start=1):
                if not isinstance(rule, dict):
                    continue
                obj = dict(rule)
                obj.setdefault('id', f'rule_{index}')
                obj.setdefault('title', obj['id'])
                obj.setdefault('family', 'Generic')
                obj.setdefault('threat_level', 'mid')
                obj.setdefault('author_or_actor', 'Unknown')
                obj.setdefault('description', '')
                obj.setdefault('path_presence_is_match', False)
                obj.setdefault('match_directories', False)
                obj.setdefault('max_file_size_bytes', 1024 * 1024)
                obj.setdefault('max_findings', settings.default_max_findings_per_rule)
                obj.setdefault('content_match_mode', 'any')
                obj.setdefault('content_min_matches', 1)
                obj.setdefault('skip_app_bundle_content', True)
                obj.setdefault('skip_binary_content', True)
                for key in (
                    'file_globs',
                    'filename_regexes',
                    'exclude_filename_regexes',
                    'path_regexes',
                    'exclude_path_regexes',
                    'content_regexes',
                    'content_extensions_include',
                    'content_extensions_exclude',
                    'plist_label_regexes',
                    'plist_program_regexes',
                    'plist_argument_regexes',
                    'process_name_regexes',
                    'process_name_exclude_regexes',
                    'process_cmdline_regexes',
                    'process_cmdline_exclude_regexes',
                    'launchd_label_regexes',
                    'launchd_label_exclude_regexes',
                    'network_proc_name_regexes',
                    'network_proc_name_exclude_regexes',
                    'network_proc_cmdline_regexes',
                    'network_proc_cmdline_exclude_regexes',
                    'network_remote_host_regexes',
                    'network_remote_host_exclude_regexes',
                    'network_local_host_regexes',
                    'network_local_host_exclude_regexes',
                    'network_protocols',
                    'network_remote_ports',
                    'network_local_ports',
                    'categories',
                    'notes',
                    'references',
                ):
                    obj.setdefault(key, [])
                normalized.append(obj)
            payload['rules'] = normalized
            self._payload = payload
            return payload

    def all_rules(self) -> List[Dict]:
        with self._lock:
            return [dict(rule) for rule in self._payload.get('rules', [])]

    def metadata(self) -> Dict:
        with self._lock:
            return {
                'schema_version': int(self._payload.get('schema_version', 1)),
                'rule_count': len(self._payload.get('rules', [])),
                'about': self._payload.get('about', ''),
            }

    def network_rules(self) -> List[Dict]:
        return [
            rule for rule in self.all_rules()
            if any(rule.get(key) for key in (
                'network_proc_name_regexes',
                'network_proc_cmdline_regexes',
                'network_remote_host_regexes',
                'network_local_host_regexes',
                'network_protocols',
                'network_remote_ports',
                'network_local_ports',
            ))
        ]
