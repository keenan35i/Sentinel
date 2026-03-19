from pathlib import Path

from src.mac_sentinel.core.host_intelligence import HostIntelligenceService
from src.mac_sentinel.core.local_storage import LocalStorage
from src.mac_sentinel.core.state import AppStateStore


class ExtendedCollector:
    def __init__(self):
        self.extensions = []
        self.login_items = []
        self.background_items = []
        self.downloads = []
        self.security = {}
        self.bundle_components = {}

    def collect_browser_extensions(self, limit: int = 150):
        return list(self.extensions)[:limit]

    def collect_login_items(self, limit: int = 60):
        return list(self.login_items)[:limit]

    def collect_background_items(self, limit: int = 120):
        return list(self.background_items)[:limit]

    def collect_recent_downloaded_candidates(self, days: int = 30, limit: int = 120):
        return list(self.downloads)[:limit]

    def collect_file_security_metadata(self, path: str):
        return dict(self.security.get(path, {}))

    def collect_bundle_components(self, app_path: str, limit: int = 40):
        return list(self.bundle_components.get(app_path, []))[:limit]

    def collect_installed_profiles(self):
        return []

    def collect_tcc_entries(self):
        return []

    def collect_diagnostic_reports(self, days: int = 7, limit: int = 200):
        return []

    def collect_user_trust_settings(self):
        return {}


def test_local_storage_ring_buffer_trims_entries(tmp_path: Path):
    storage = LocalStorage(tmp_path / 'state.db')
    for index in range(7):
      storage.append_entry('scan_logs', {'message': f'log {index}'}, retention=3)
    rows = storage.list_entries('scan_logs', 10)
    assert [row['message'] for row in rows] == ['log 4', 'log 5', 'log 6']


def test_browser_extension_with_native_messaging_and_all_urls_is_flagged():
    collector = ExtendedCollector()
    collector.extensions = [
        {
            'browser': 'Chrome',
            'profile': 'Default',
            'extension_id': 'abc',
            'manifest_path': '/Users/test/Library/Application Support/Google/Chrome/Default/Extensions/abc/1/manifest.json',
            'name': 'sideload helper',
            'version': '1.0.0',
            'permissions': ['nativeMessaging', 'storage'],
            'host_permissions': ['<all_urls>'],
            'update_url': '',
            'manifest_version': 3,
            'has_native_messaging': True,
            'is_unpacked': True,
        }
    ]
    findings = HostIntelligenceService(collector).collect_findings()
    assert any(item.rule_id == 'browser_extension_high_risk_capabilities' for item in findings)


def test_user_writable_login_item_is_flagged_as_persistence():
    collector = ExtendedCollector()
    collector.login_items = [
        {'name': 'Updater', 'path': '/Users/test/Downloads/Updater.app', 'hidden': True},
    ]
    findings = HostIntelligenceService(collector).collect_findings()
    matched = [item for item in findings if item.rule_id == 'user_writable_persistence_target']
    assert len(matched) == 1
    assert matched[0].threat_level == 'mid'


def test_downloaded_app_with_unsigned_nested_helper_gets_provenance_finding():
    collector = ExtendedCollector()
    app_path = '/Users/test/Downloads/FakeApp.app'
    helper_path = '/Users/test/Downloads/FakeApp.app/Contents/Helpers/helper'
    collector.downloads = [{'path': app_path, 'suffix': '.app', 'executable': False}]
    collector.security[app_path] = {
        'has_quarantine': True,
        'spctl_accepted': False,
        'notarized': False,
        'signature_type': 'unsigned',
        'spctl_assessment': 'rejected',
        'origin_url': 'https://example.test/fake',
    }
    collector.bundle_components[app_path] = [
        {'path': helper_path, 'metadata': {'signature_type': 'unsigned'}},
    ]
    findings = HostIntelligenceService(collector).collect_findings()
    rule_ids = {item.rule_id for item in findings}
    assert 'downloaded_app_not_notarized' in rule_ids
    assert 'unsigned_nested_bundle_component' in rule_ids


def test_wait_for_revision_change_returns_new_revisions(tmp_path: Path):
    state = AppStateStore(storage=LocalStorage(tmp_path / 'state.db'))
    before = state.revisions()
    state.append_scan_log('hello world')
    after = state.wait_for_revision_change(previous=before, timeout=0.05)
    assert after['scan_logs'] == before['scan_logs'] + 1
