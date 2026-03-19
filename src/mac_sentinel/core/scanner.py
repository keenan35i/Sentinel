from __future__ import annotations

import os
import re
from typing import Dict, Iterable, List, Optional

from ..models import Finding
from .content_filters import should_scan_content
from .runtime import PatternEnumerationTimeout, ScanStopRequested


SEVERITY_ORDER = {'high': 0, 'mid': 1, 'low': 2}


class RuleEngine:
    def __init__(self, collector):
        self.collector = collector

    def _regex_any(self, patterns: Iterable[str], text: str) -> Optional[str]:
        for pattern in patterns or []:
            try:
                if re.search(pattern, text or '', re.I | re.M):
                    return pattern
            except re.error:
                continue
        return None

    def _count_regex_hits(self, patterns: Iterable[str], text: str) -> tuple[int, str]:
        count = 0
        first = ''
        for pattern in patterns or []:
            try:
                if re.search(pattern, text or '', re.I | re.M):
                    count += 1
                    first = first or pattern
            except re.error:
                continue
        return count, first

    def _ports_match(self, required_ports: List[int], observed: Optional[int]) -> bool:
        if not required_ports:
            return True
        if observed is None:
            return False
        return int(observed) in {int(x) for x in required_ports}

    def _protocols_match(self, required_protocols: List[str], observed: str) -> bool:
        if not required_protocols:
            return True
        return (observed or '').upper() in {str(x).upper() for x in required_protocols}

    def _path_excluded(self, rule: Dict, path: str) -> bool:
        filename = os.path.basename(path)
        if self._regex_any(rule.get('exclude_filename_regexes', []), filename):
            return True
        if self._regex_any(rule.get('exclude_path_regexes', []), path):
            return True
        return False

    def build_finding(self, rule: Dict, source: str, evidence_type: str, **kwargs) -> Finding:
        return Finding(
            rule_id=rule['id'],
            title=rule['title'],
            family=rule.get('family', 'Generic'),
            threat_level=rule.get('threat_level', 'mid'),
            author_or_actor=rule.get('author_or_actor', 'Unknown'),
            description=rule.get('description', ''),
            source=source,
            evidence_type=evidence_type,
            **kwargs,
        )

    def evaluate_rule(self, rule: Dict, source: str = 'scan') -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._match_rule_on_files(rule, source))
        findings.extend(self._match_rule_on_processes(rule, source))
        findings.extend(self._match_rule_on_launchctl(rule, source))
        findings.extend(self._match_rule_on_network(rule, source))
        return findings

    def evaluate_network_only(self, rule: Dict, source: str = 'live') -> List[Finding]:
        return self._match_rule_on_network(rule, source)

    def _content_match(self, rule: Dict, text: str) -> tuple[bool, str]:
        patterns = rule.get('content_regexes', [])
        if not patterns:
            return True, ''
        hit_count, first_hit = self._count_regex_hits(patterns, text)
        mode = str(rule.get('content_match_mode', 'any')).lower()
        required = max(1, int(rule.get('content_min_matches', 1)))
        if mode == 'all':
            return hit_count == len(patterns), first_hit
        return hit_count >= required, first_hit

    def _match_rule_on_files(self, rule: Dict, source: str) -> List[Finding]:
        if not rule.get('file_globs'):
            return []

        uses_file_fields = any(rule.get(key) for key in (
            'file_globs',
            'filename_regexes',
            'path_regexes',
            'content_regexes',
            'plist_label_regexes',
            'plist_program_regexes',
            'plist_argument_regexes',
        ))
        if not uses_file_fields:
            return []

        findings: List[Finding] = []
        max_findings = max(1, int(rule.get('max_findings', 50)))
        for pattern in rule['file_globs']:
            for path in self.collector.glob_paths(pattern):
                if self._path_excluded(rule, path):
                    continue
                if os.path.isdir(path) and not rule.get('match_directories', False):
                    continue

                filename = os.path.basename(path)
                filename_hit = self._regex_any(rule.get('filename_regexes', []), filename) if rule.get('filename_regexes') else None
                if rule.get('filename_regexes') and not filename_hit:
                    continue

                path_hit = self._regex_any(rule.get('path_regexes', []), path) if rule.get('path_regexes') else None
                if rule.get('path_regexes') and not path_hit:
                    continue

                plist_hit = None
                plist_rules_present = any(rule.get(name) for name in ('plist_label_regexes', 'plist_program_regexes', 'plist_argument_regexes'))
                if plist_rules_present:
                    plist_obj = self.collector.parse_plist(path)
                    label_hit = self._regex_any(rule.get('plist_label_regexes', []), plist_obj.get('Label', '')) if rule.get('plist_label_regexes') else None
                    program_hit = self._regex_any(rule.get('plist_program_regexes', []), plist_obj.get('Program', '')) if rule.get('plist_program_regexes') else None
                    arg_text = ' '.join(plist_obj.get('ProgramArguments', []))
                    arg_hit = self._regex_any(rule.get('plist_argument_regexes', []), arg_text) if rule.get('plist_argument_regexes') else None
                    if rule.get('plist_label_regexes') and not label_hit:
                        continue
                    if rule.get('plist_program_regexes') and not program_hit:
                        continue
                    if rule.get('plist_argument_regexes') and not arg_hit:
                        continue
                    plist_hit = label_hit or program_hit or arg_hit

                content_hit = None
                if rule.get('content_regexes'):
                    if not should_scan_content(path, rule):
                        continue
                    text = self.collector.read_text(
                        path,
                        int(rule.get('max_file_size_bytes', 1024 * 1024)),
                        skip_binary=bool(rule.get('skip_binary_content', True)),
                    )
                    content_ok, content_hit = self._content_match(rule, text)
                    if not content_ok:
                        continue

                indicator_hits = [hit for hit in (filename_hit, path_hit, plist_hit, content_hit) if hit]
                if not indicator_hits and not rule.get('path_presence_is_match'):
                    continue

                evidence_type = 'plist' if plist_hit else ('content' if content_hit else 'path')
                findings.append(self.build_finding(
                    rule,
                    source=source,
                    evidence_type=evidence_type,
                    matched_path=path,
                    matched_regex=content_hit or plist_hit or path_hit or filename_hit or '',
                ))
                if len(findings) >= max_findings:
                    return findings
        return findings

    def _match_rule_on_processes(self, rule: Dict, source: str) -> List[Finding]:
        if not rule.get('process_name_regexes') and not rule.get('process_cmdline_regexes'):
            return []
        findings: List[Finding] = []
        for process in self.collector.collect_processes():
            if self._regex_any(rule.get('process_name_exclude_regexes', []), process['comm']):
                continue
            if self._regex_any(rule.get('process_cmdline_exclude_regexes', []), process['args']):
                continue
            name_hit = self._regex_any(rule.get('process_name_regexes', []), process['comm']) if rule.get('process_name_regexes') else None
            if rule.get('process_name_regexes') and not name_hit:
                continue
            cmd_hit = self._regex_any(rule.get('process_cmdline_regexes', []), process['args']) if rule.get('process_cmdline_regexes') else None
            if rule.get('process_cmdline_regexes') and not cmd_hit:
                continue
            findings.append(self.build_finding(
                rule,
                source=source,
                evidence_type='process',
                matched_pid=process['pid'],
                process_name=process['comm'],
                process_cmdline=process['args'],
                matched_regex=name_hit or cmd_hit or '',
            ))
        return findings

    def _match_rule_on_launchctl(self, rule: Dict, source: str) -> List[Finding]:
        if not rule.get('launchd_label_regexes'):
            return []
        findings: List[Finding] = []
        for item in self.collector.collect_launchctl_labels():
            label = item.get('label', '')
            if self._regex_any(rule.get('launchd_label_exclude_regexes', []), label):
                continue
            label_hit = self._regex_any(rule.get('launchd_label_regexes', []), label)
            if not label_hit:
                continue
            findings.append(self.build_finding(
                rule,
                source=source,
                evidence_type='launchctl',
                matched_pid=item.get('pid'),
                launchd_label=label,
                matched_regex=label_hit,
            ))
        return findings

    def _match_rule_on_network(self, rule: Dict, source: str) -> List[Finding]:
        network_keys = (
            'network_proc_name_regexes',
            'network_proc_cmdline_regexes',
            'network_remote_host_regexes',
            'network_local_host_regexes',
            'network_protocols',
            'network_remote_ports',
            'network_local_ports',
        )
        if not any(rule.get(key) for key in network_keys):
            return []

        findings: List[Finding] = []
        proc_map = {item['pid']: item for item in self.collector.collect_processes()}
        for conn in self.collector.collect_network_connections():
            process = proc_map.get(conn['pid'], {})
            if self._regex_any(rule.get('network_proc_name_exclude_regexes', []), conn.get('command', '')):
                continue
            if self._regex_any(rule.get('network_proc_cmdline_exclude_regexes', []), process.get('args', '')):
                continue
            if self._regex_any(rule.get('network_remote_host_exclude_regexes', []), conn.get('remote_address', '')):
                continue
            if self._regex_any(rule.get('network_local_host_exclude_regexes', []), conn.get('local_address', '')):
                continue

            name_hit = self._regex_any(rule.get('network_proc_name_regexes', []), conn.get('command', '')) if rule.get('network_proc_name_regexes') else None
            if rule.get('network_proc_name_regexes') and not name_hit:
                continue

            cmd_hit = self._regex_any(rule.get('network_proc_cmdline_regexes', []), process.get('args', '')) if rule.get('network_proc_cmdline_regexes') else None
            if rule.get('network_proc_cmdline_regexes') and not cmd_hit:
                continue

            remote_hit = self._regex_any(rule.get('network_remote_host_regexes', []), conn.get('remote_address', '')) if rule.get('network_remote_host_regexes') else None
            if rule.get('network_remote_host_regexes') and not remote_hit:
                continue

            local_hit = self._regex_any(rule.get('network_local_host_regexes', []), conn.get('local_address', '')) if rule.get('network_local_host_regexes') else None
            if rule.get('network_local_host_regexes') and not local_hit:
                continue

            if not self._ports_match(rule.get('network_remote_ports', []), conn.get('remote_port')):
                continue
            if not self._ports_match(rule.get('network_local_ports', []), conn.get('local_port')):
                continue
            if not self._protocols_match(rule.get('network_protocols', []), conn.get('protocol', '')):
                continue

            findings.append(self.build_finding(
                rule,
                source=source,
                evidence_type='network',
                matched_pid=conn['pid'],
                process_name=conn.get('command', ''),
                process_cmdline=process.get('args', ''),
                local_address=conn.get('local_address', ''),
                local_port=conn.get('local_port'),
                remote_address=conn.get('remote_address', ''),
                remote_port=conn.get('remote_port'),
                protocol=conn.get('protocol', ''),
                matched_regex=name_hit or cmd_hit or remote_hit or local_hit or '',
            ))
        return findings


class ScanService:
    def __init__(self, collector, rule_repository, state_store, intelligence=None):
        self.collector = collector
        self.rule_repository = rule_repository
        self.state_store = state_store
        self.intelligence = intelligence
        self.rule_engine = RuleEngine(collector)
        self.collector.configure_controls(
            should_pause=lambda: self.state_store.scan_status().get('paused', False),
            should_stop=lambda: self.state_store.scan_status().get('stop_requested', False),
        )

    def _sample_runtime_baseline(self) -> Dict[str, int]:
        processes = self.collector.collect_processes(fresh=True)
        launch_items = self.collector.collect_launchctl_labels(fresh=True)
        connections = self.collector.collect_network_connections(fresh=True)
        return {
            'process_count': len(processes),
            'launchd_count': len(launch_items),
            'connection_count': len(connections),
        }

    def run_full_scan(self) -> List[Dict]:
        self.collector.clear()
        rules = self.rule_repository.all_rules()
        status = self.state_store.scan_status()
        if not status.get('running'):
            self.state_store.begin_scan(total_rules=len(rules))
        else:
            self.state_store.update_scan_progress(0, len(rules), 'Preparing scan')

        self.state_store.append_scan_log(
            f'Starting full scan with {len(rules)} loaded JSON rules.',
            phase='start',
        )

        baseline = self._sample_runtime_baseline()
        self.state_store.append_scan_log(
            f"Baseline collected: {baseline['process_count']} processes, {baseline['launchd_count']} launchd labels, {baseline['connection_count']} active network sockets.",
            phase='baseline',
        )
        if baseline['process_count'] == 0:
            self.state_store.append_scan_log(
                'No processes were returned by ps. This may indicate an environment or permissions issue.',
                level='warning',
                phase='baseline',
            )

        findings: List[Finding] = []
        for index, rule in enumerate(rules, start=1):
            if self.state_store.scan_status().get('stop_requested'):
                raise ScanStopRequested('Scan stop requested by user.')

            self.state_store.update_scan_progress(index - 1, len(rules), rule.get('title', ''))
            self.state_store.append_scan_log(
                f"[{index}/{len(rules)}] Evaluating rule: {rule.get('title', rule.get('id', 'unknown'))} ({rule.get('threat_level', 'mid')}).",
                phase='rule',
            )
            try:
                matched = self.rule_engine.evaluate_rule(rule, source='scan')
            except PatternEnumerationTimeout as exc:
                matched = []
                self.state_store.append_scan_log(
                    f"Skipped rule {rule.get('id', 'unknown')} because path enumeration timed out: {exc}",
                    level='warning',
                    phase='rule-timeout',
                    extra={'rule_id': rule.get('id', '')},
                )
            except ScanStopRequested:
                self.state_store.cancel_scan()
                return []
            except Exception as exc:
                matched = []
                self.state_store.append_scan_log(
                    f"Skipped rule {rule.get('id', 'unknown')} because it raised an error: {exc}",
                    level='error',
                    phase='rule-error',
                    extra={'rule_id': rule.get('id', '')},
                )

            findings.extend(matched)
            if matched:
                extra = {'rule_id': rule.get('id', ''), 'count': len(matched)}
                if len(matched) >= int(rule.get('max_findings', 50)):
                    self.state_store.append_scan_log(
                        f"Matched {len(matched)} finding(s) for rule {rule.get('id', 'unknown')} and hit the per-rule cap. This rule is likely noisy on this host.",
                        level='warning',
                        phase='match-capped',
                        extra=extra,
                    )
                else:
                    self.state_store.append_scan_log(
                        f"Matched {len(matched)} finding(s) for rule {rule.get('id', 'unknown')}.",
                        level='warning',
                        phase='match',
                        extra=extra,
                    )
            else:
                self.state_store.append_scan_log(
                    f"No match for rule {rule.get('id', 'unknown')}",
                    phase='rule-result',
                    extra={'rule_id': rule.get('id', '')},
                )
            self.state_store.update_scan_progress(index, len(rules), rule.get('title', ''))

        if self.intelligence is not None:
            try:
                host_findings = self.intelligence.collect_findings(source='scan')
                findings.extend(host_findings)
                if host_findings:
                    self.state_store.append_scan_log(
                        f'Added {len(host_findings)} structured host-intelligence finding(s) from profile, TCC, downloaded-item, trust, and diagnostic-report analysis.',
                        level='warning',
                        phase='host-intel',
                    )
            except Exception as exc:
                self.state_store.append_scan_log(
                    f'Host-intelligence checks failed but the scan continued: {exc}',
                    level='warning',
                    phase='host-intel-error',
                )

        deduped = self._dedupe_findings(findings)
        deduped.sort(key=lambda item: (
            SEVERITY_ORDER.get(item.threat_level, 99),
            item.title,
            item.matched_path,
            item.matched_pid or 0,
        ))
        payload = [item.to_dict() for item in deduped]
        if payload:
            self.state_store.append_scan_log(
                f'Scan completed with {len(payload)} finding(s) after deduplication.',
                level='warning',
                phase='complete',
            )
        else:
            self.state_store.append_scan_log(
                'Scan completed with zero matched findings. Review the scan log and diagnostics panel to confirm the scanner actually inspected the host.',
                phase='complete',
            )
        self.state_store.set_scan_results(payload)
        return payload

    def collect_network_activity(self) -> Dict[str, List[Dict]]:
        processes = self.collector.collect_processes(fresh=True)
        proc_map = {item['pid']: item for item in processes}
        connections = self.collector.collect_network_connections(fresh=True)
        enriched_connections = []
        for conn in connections:
            proc = proc_map.get(conn.get('pid'), {})
            enriched = dict(conn)
            enriched['process_cmdline'] = proc.get('args', '')
            enriched['process_name'] = proc.get('comm', conn.get('command', ''))
            enriched_connections.append(enriched)
        findings: List[Finding] = []
        for rule in self.rule_repository.network_rules():
            findings.extend(self.rule_engine.evaluate_network_only(rule, source='live'))
        if self.intelligence is not None:
            try:
                host_findings = self.intelligence.collect_findings(source='scan')
                findings.extend(host_findings)
                if host_findings:
                    self.state_store.append_scan_log(
                        f'Added {len(host_findings)} structured host-intelligence finding(s) from profile, TCC, and diagnostic-report analysis.',
                        level='warning',
                        phase='host-intel',
                    )
            except Exception as exc:
                self.state_store.append_scan_log(
                    f'Host-intelligence checks failed but the scan continued: {exc}',
                    level='warning',
                    phase='host-intel-error',
                )

        deduped = self._dedupe_findings(findings)
        deduped.sort(key=lambda item: (
            SEVERITY_ORDER.get(item.threat_level, 99),
            item.title,
            item.remote_address,
            item.remote_port or 0,
        ))
        return {
            'connections': enriched_connections,
            'findings': [item.to_dict() for item in deduped],
        }

    def run_network_snapshot(self) -> List[Dict]:
        return self.collect_network_activity()['findings']

    def _dedupe_findings(self, findings: List[Finding]) -> List[Finding]:
        seen = set()
        unique: List[Finding] = []
        for item in findings:
            key = (
                item.rule_id,
                item.evidence_type,
                item.matched_path,
                item.matched_pid,
                item.launchd_label,
                item.remote_address,
                item.remote_port,
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        return unique
