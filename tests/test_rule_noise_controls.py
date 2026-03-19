from pathlib import Path

from src.mac_sentinel.core.scanner import ScanService
from src.mac_sentinel.core.state import AppStateStore


class FakeRuleRepository:
    def __init__(self, rules):
        self._rules = rules

    def all_rules(self):
        return list(self._rules)

    def network_rules(self):
        return []


class NoiseCollector:
    def __init__(self, paths):
        self.paths = paths

    def clear(self):
        return None

    def configure_controls(self, should_pause, should_stop):
        return None

    def glob_paths(self, pattern: str):
        return list(self.paths)

    def read_text(self, path: str, max_bytes: int, skip_binary: bool = True):
        return ''

    def parse_plist(self, path: str):
        return {"Label": "", "Program": "", "ProgramArguments": []}

    def collect_processes(self, fresh: bool = False):
        return []

    def collect_launchctl_labels(self, fresh: bool = False):
        return []

    def collect_network_connections(self, fresh: bool = False):
        return []


def test_directory_only_matches_are_ignored_by_default(tmp_path):
    suspicious_dir = tmp_path / "GoogleUpdater"
    suspicious_dir.mkdir()
    rule = {
        "id": "dir_noise",
        "title": "Dir noise",
        "family": "Test",
        "threat_level": "mid",
        "author_or_actor": "Unit Test",
        "description": "Should not match directories by default.",
        "file_globs": [str(tmp_path / "**")],
        "filename_regexes": [],
        "exclude_filename_regexes": [],
        "path_regexes": [r"(?i)/GoogleUpdater$"],
        "exclude_path_regexes": [],
        "content_regexes": [],
        "plist_label_regexes": [],
        "plist_program_regexes": [],
        "plist_argument_regexes": [],
        "process_name_regexes": [],
        "process_cmdline_regexes": [],
        "launchd_label_regexes": [],
        "network_proc_name_regexes": [],
        "network_proc_cmdline_regexes": [],
        "network_remote_host_regexes": [],
        "network_local_host_regexes": [],
        "network_protocols": [],
        "network_remote_ports": [],
        "network_local_ports": [],
        "path_presence_is_match": True,
        "max_findings": 10,
    }
    scanner = ScanService(collector=NoiseCollector([str(suspicious_dir)]), rule_repository=FakeRuleRepository([rule]), state_store=AppStateStore())
    scanner.state_store.begin_scan(total_rules=1)
    results = scanner.run_full_scan()
    assert results == []


def test_rule_cap_limits_noisy_results(tmp_path):
    paths = []
    for index in range(30):
        file_path = tmp_path / f"Installer_{index}.pkg"
        file_path.write_text("x")
        paths.append(str(file_path))
    rule = {
        "id": "cap_noise",
        "title": "Cap noise",
        "family": "Test",
        "threat_level": "mid",
        "author_or_actor": "Unit Test",
        "description": "Should cap noisy results.",
        "file_globs": [str(tmp_path / "*")],
        "filename_regexes": [r"(?i)installer_\d+\.pkg$"],
        "exclude_filename_regexes": [],
        "path_regexes": [],
        "exclude_path_regexes": [],
        "content_regexes": [],
        "plist_label_regexes": [],
        "plist_program_regexes": [],
        "plist_argument_regexes": [],
        "process_name_regexes": [],
        "process_cmdline_regexes": [],
        "launchd_label_regexes": [],
        "network_proc_name_regexes": [],
        "network_proc_cmdline_regexes": [],
        "network_remote_host_regexes": [],
        "network_local_host_regexes": [],
        "network_protocols": [],
        "network_remote_ports": [],
        "network_local_ports": [],
        "path_presence_is_match": True,
        "max_findings": 5,
    }
    state = AppStateStore()
    scanner = ScanService(collector=NoiseCollector(paths), rule_repository=FakeRuleRepository([rule]), state_store=state)
    state.begin_scan(total_rules=1)
    results = scanner.run_full_scan()
    assert len(results) == 5
    assert any('hit the per-rule cap' in entry['message'] for entry in state.scan_logs())
