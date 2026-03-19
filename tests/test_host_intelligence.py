from fastapi.testclient import TestClient

from src.mac_sentinel.core.host_intelligence import HostIntelligenceService
from src.mac_sentinel.core.scanner import ScanService
from src.mac_sentinel.core.state import AppStateStore
from src.mac_sentinel.main import create_application


class EmptyRuleRepository:
    def all_rules(self):
        return []

    def network_rules(self):
        return []


class HostIntelCollector:
    def __init__(self):
        self._profiles = []
        self._tcc_entries = []
        self._diagnostic_reports = []

    def clear(self):
        return None

    def configure_controls(self, should_pause, should_stop):
        return None

    def glob_paths(self, pattern: str):
        return []

    def read_text(self, path: str, max_bytes: int, skip_binary: bool = True):
        return ''

    def parse_plist(self, path: str):
        return {'Label': '', 'Program': '', 'ProgramArguments': []}

    def collect_processes(self, fresh: bool = False):
        return []

    def collect_launchctl_labels(self, fresh: bool = False):
        return []

    def collect_network_connections(self, fresh: bool = False):
        return []

    def collect_installed_profiles(self):
        return list(self._profiles)

    def collect_tcc_entries(self):
        return list(self._tcc_entries)

    def collect_diagnostic_reports(self, days: int = 7, limit: int = 200):
        return list(self._diagnostic_reports)[:limit]



def test_sensitive_installed_profile_is_contextual_not_automatic_pegasus_verdict():
    collector = HostIntelCollector()
    collector._profiles = [
        {
            'identifier': 'com.example.pppc',
            'display_name': 'Example Access Profile',
            'organization': 'Unknown Org',
            'payload_types': [
                'com.apple.TCC.configuration-profile-policy',
                'com.apple.security.root',
            ],
            'payload_text': 'Accessibility AppleEvents SystemPolicyAllFiles PayloadRemovalDisallowed',
            'removal_disallowed': True,
        }
    ]
    service = HostIntelligenceService(collector)
    findings = service.collect_findings()
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == 'installed_profile_sensitive_payloads'
    assert finding.threat_level == 'mid'
    assert 'not proof of spyware by itself' in finding.description



def test_suspicious_tcc_grant_requires_user_writable_path_and_high_risk_service():
    collector = HostIntelCollector()
    collector._tcc_entries = [
        {
            'service': 'kTCCServiceSystemPolicyAllFiles',
            'client': '/Users/test/Downloads/fake-updater',
            'client_type': 1,
            'allowed': True,
            'db_path': '/Users/test/Library/Application Support/com.apple.TCC/TCC.db',
        },
        {
            'service': 'kTCCServiceSystemPolicyAllFiles',
            'client': '/Applications/Visual Studio Code.app/Contents/MacOS/Electron',
            'client_type': 1,
            'allowed': True,
            'db_path': '/Users/test/Library/Application Support/com.apple.TCC/TCC.db',
        },
    ]
    service = HostIntelligenceService(collector)
    findings = service.collect_findings()
    assert len(findings) == 1
    assert findings[0].rule_id == 'tcc_suspicious_user_writable_grant'
    assert findings[0].threat_level == 'high'
    assert '/Users/test/Downloads/fake-updater' in findings[0].matched_path



def test_recent_blastdoor_or_imagent_crashes_are_low_severity_context_only():
    collector = HostIntelCollector()
    collector._diagnostic_reports = [
        {'process': 'MessagesBlastDoorService', 'path': '/tmp/a.ips', 'mtime': 1},
        {'process': 'MessagesBlastDoorService', 'path': '/tmp/b.ips', 'mtime': 1},
        {'process': 'MessagesBlastDoorService', 'path': '/tmp/c.ips', 'mtime': 1},
    ]
    service = HostIntelligenceService(collector)
    findings = service.collect_findings()
    assert len(findings) == 1
    assert findings[0].rule_id == 'recent_messaging_crash_burst_context'
    assert findings[0].threat_level == 'low'



def test_scan_service_merges_host_intelligence_findings_without_rules():
    collector = HostIntelCollector()
    collector._tcc_entries = [
        {
            'service': 'kTCCServiceAccessibility',
            'client': '/Users/test/Downloads/fake-helper',
            'client_type': 1,
            'allowed': True,
            'db_path': '/Users/test/Library/Application Support/com.apple.TCC/TCC.db',
        }
    ]
    state = AppStateStore()
    intel = HostIntelligenceService(collector)
    scanner = ScanService(collector=collector, rule_repository=EmptyRuleRepository(), state_store=state, intelligence=intel)
    state.begin_scan(total_rules=0)
    findings = scanner.run_full_scan()
    assert len(findings) == 1
    assert findings[0]['rule_id'] == 'tcc_suspicious_user_writable_grant'
    assert any('structured host-intelligence finding' in entry['message'] for entry in state.scan_logs())



def test_intelligence_summary_endpoint_and_diagnostics_include_advanced_checks():
    app = create_application()
    client = TestClient(app)

    summary = client.get('/api/intelligence/summary')
    assert summary.status_code == 200
    assert 'profile_inventory' in summary.json()

    diagnostics = client.get('/api/diagnostics')
    assert diagnostics.status_code == 200
    assert 'advanced_checks' in diagnostics.json()
