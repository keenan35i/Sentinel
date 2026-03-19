import json
from pathlib import Path

from fastapi.testclient import TestClient

from src.mac_sentinel.core.forensics import LocalArtifactIntelligenceService
from src.mac_sentinel.core.host_intelligence import HostIntelligenceService
from src.mac_sentinel.core.state import AppStateStore
from src.mac_sentinel.main import create_application


class RichHostIntelCollector:
    def collect_installed_profiles(self):
        return []

    def collect_tcc_entries(self):
        return []

    def collect_diagnostic_reports(self, days: int = 7, limit: int = 200):
        return []

    def collect_recent_downloaded_candidates(self, days: int = 30, limit: int = 120):
        return [
            {
                'path': '/Users/test/Downloads/Unknown Helper.app',
                'mtime': 1,
                'size': 100,
                'suffix': '.app',
                'executable': True,
            }
        ]

    def collect_file_security_metadata(self, path: str):
        return {
            'has_quarantine': True,
            'spctl_accepted': False,
            'codesign_authority': '',
            'signature_type': 'unsigned',
            'quarantine': '0081;demo',
        }

    def collect_user_trust_settings(self):
        return {'admin_has_custom_settings': True, 'user_has_custom_settings': False}


def test_forensic_import_supports_apple_notification_and_stix_correlation(tmp_path: Path):
    apple_notice = tmp_path / 'apple_notice.txt'
    apple_notice.write_text('Apple threat notification: you may have been targeted by mercenary spyware.', encoding='utf-8')

    stix_file = tmp_path / 'sample.stix2'
    stix_file.write_text(json.dumps({
        'type': 'bundle',
        'objects': [
            {'type': 'indicator', 'pattern': "[file:name = 'pegasus_marker_value']"}
        ],
    }), encoding='utf-8')

    sysdiag = tmp_path / 'sysdiagnose'
    sysdiag.mkdir()
    (sysdiag / 'Shutdown.log').write_text('MessagesBlastDoorService pegasus_marker_value imagent', encoding='utf-8')

    state = AppStateStore()
    service = LocalArtifactIntelligenceService(state_store=state)
    result = service.import_paths([str(stix_file), str(apple_notice), str(sysdiag)])

    rule_ids = {item['rule_id'] for item in result['findings']}
    assert 'imported_apple_threat_notification' in rule_ids
    assert 'stix_indicator_match_in_imported_artifact' in rule_ids
    assert 'correlated_apple_notification_plus_stix' in rule_ids
    assert 'correlated_sysdiagnose_plus_stix' in rule_ids
    assert state.intelligence_summary()['local_only'] is True


def test_intelligence_api_import_and_state_endpoints(tmp_path: Path):
    stix_file = tmp_path / 'sample.stix2'
    stix_file.write_text(json.dumps({
        'type': 'bundle',
        'objects': [{'type': 'indicator', 'pattern': "[file:name = 'graphite']"}],
    }), encoding='utf-8')
    notice = tmp_path / 'notice.txt'
    notice.write_text('Apple threat notification and mercenary spyware wording.', encoding='utf-8')

    app = create_application()
    client = TestClient(app)

    response = client.post('/api/intelligence/import', json={'paths': [str(stix_file), str(notice)]})
    assert response.status_code == 200
    payload = response.json()
    assert payload['ok'] is True
    assert payload['imported_count'] == 2

    state = client.get('/api/intelligence/state')
    assert state.status_code == 200
    body = state.json()
    assert body['summary']['artifact_count'] == 2
    assert isinstance(body['findings'], list)


def test_state_store_trims_logs_when_limit_is_exceeded():
    state = AppStateStore()
    for index in range(8):
        state.append_scan_log(f'scan {index}', limit=5)
    for index in range(9):
        state.append_monitor_log(f'monitor {index}', limit=4)
    for index in range(7):
        state.append_intelligence_log(f'intel {index}')

    assert len(state.scan_logs()) == 5
    assert state.scan_logs()[0]['message'] == 'scan 3'
    assert len(state.monitor_logs()) == 4
    assert state.monitor_logs()[0]['message'] == 'monitor 5'
    assert len(state.intelligence_logs()) <= 7


def test_host_intelligence_flags_unsigned_quarantined_download_and_trust_context():
    collector = RichHostIntelCollector()
    service = HostIntelligenceService(collector)
    findings = service.collect_findings()
    rule_ids = {item.rule_id for item in findings}
    assert 'quarantined_unsigned_downloaded_executable' in rule_ids
    assert 'custom_trust_settings_present' in rule_ids
