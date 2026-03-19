from src.mac_sentinel.core.state import AppStateStore
from src.mac_sentinel.core.runtime import RuntimeCollector


def test_revisions_only_bump_for_changed_connection_snapshots():
    state = AppStateStore()
    first = [{'pid': 1, 'command': 'python', 'protocol': 'TCP'}]
    assert state.set_monitor_connections(first) is True
    first_rev = state.revisions()['monitor_connections']
    assert state.set_monitor_connections(first) is False
    assert state.revisions()['monitor_connections'] == first_rev
    assert state.set_monitor_connections(first + [{'pid': 2, 'command': 'curl', 'protocol': 'TCP'}]) is True
    assert state.revisions()['monitor_connections'] == first_rev + 1


def test_guess_service_and_parse_pair():
    collector = RuntimeCollector()
    host, port, remote_host, remote_port = collector._parse_pair('127.0.0.1:5555->1.2.3.4:443 (ESTABLISHED)')
    assert host == '127.0.0.1'
    assert port == 5555
    assert remote_host == '1.2.3.4'
    assert remote_port == 443
    assert collector._guess_service(443) == 'HTTPS'
