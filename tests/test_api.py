from fastapi.testclient import TestClient

from src.mac_sentinel.main import create_application


def test_health_and_diagnostics_endpoints():
    app = create_application()
    client = TestClient(app)

    health = client.get('/api/health')
    assert health.status_code == 200
    assert health.json()['ok'] is True

    diagnostics = client.get('/api/diagnostics')
    assert diagnostics.status_code == 200
    payload = diagnostics.json()
    assert 'commands' in payload
    assert 'notes' in payload

    root = client.get('/')
    assert root.status_code == 200
    assert root.json()['ok'] is True


def test_scan_pause_resume_stop_endpoints():
    app = create_application()
    app.state.services['state'].begin_scan(total_rules=5)
    client = TestClient(app)

    pause = client.post('/api/scan/pause')
    assert pause.status_code == 200
    assert pause.json()['paused'] is True

    resume = client.post('/api/scan/resume')
    assert resume.status_code == 200
    assert resume.json()['paused'] is False

    stop = client.post('/api/scan/stop')
    assert stop.status_code == 200
    assert stop.json()['stop_requested'] is True
