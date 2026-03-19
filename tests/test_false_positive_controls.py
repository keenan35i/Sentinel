from pathlib import Path

from src.mac_sentinel.core.content_filters import should_scan_content
from src.mac_sentinel.core.scanner import RuleEngine


class MinimalCollector:
    def __init__(self, path: str, text_payload: str):
        self.path = path
        self.text_payload = text_payload

    def glob_paths(self, pattern: str):
        return [self.path]

    def read_text(self, path: str, max_bytes: int, skip_binary: bool = True):
        return self.text_payload

    def parse_plist(self, path: str):
        return {'Label': '', 'Program': '', 'ProgramArguments': []}

    def collect_processes(self, fresh: bool = False):
        return []

    def collect_launchctl_labels(self, fresh: bool = False):
        return []

    def collect_network_connections(self, fresh: bool = False):
        return []


def test_should_skip_vendor_fontawesome_asset():
    rule = {'content_extensions_include': ['.js']}
    path = '/Users/test/Documents/projects/site/assets/site/fontawesome/js/brands.js'
    assert should_scan_content(path, rule) is False


def test_should_skip_generated_renderer_asset():
    rule = {'content_extensions_include': ['.js']}
    path = '/Users/test/Documents/projects/mac_sentinel/dist/renderer/assets/index-BoKPFMZD.js'
    assert should_scan_content(path, rule) is False


def test_nested_project_asset_does_not_match_top_level_stager_rule(tmp_path):
    nested = tmp_path / 'Downloads' / 'iu-marketplace' / 'assets' / 'site' / 'fontawesome' / 'js' / 'brands.js'
    nested.parent.mkdir(parents=True)
    nested.write_text('Chrome Login Data\narchive')
    rule = {
        'id': 'telegram_notes_browser_archive_terms',
        'title': 'Collection script',
        'family': 'Test',
        'threat_level': 'high',
        'author_or_actor': 'Unit Test',
        'description': 'Should not match nested project assets.',
        'file_globs': [str(tmp_path / 'Downloads' / '**')],
        'filename_regexes': [],
        'exclude_filename_regexes': [],
        'path_regexes': [
            r'(?i)^.*/Downloads/[^/]+\.(command|sh|zsh|bash|py|plist|scpt|applescript|txt|json|js|ts)$',
        ],
        'exclude_path_regexes': [r'(?i)/fontawesome/'],
        'content_regexes': [r'(?i)(Chrome Login Data)', r'(?i)(archive|copy|upload)'],
        'content_min_matches': 2,
        'content_extensions_include': ['.js'],
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
    }
    engine = RuleEngine(MinimalCollector(str(nested), 'Chrome Login Data\narchive'))
    assert engine.evaluate_rule(rule) == []
