from __future__ import annotations

import threading
import time
from typing import Dict, List, Tuple


class MonitorService:
    def __init__(self, scan_service, state_store, interval_seconds: int = 4):
        self.scan_service = scan_service
        self.state_store = state_store
        self.interval_seconds = interval_seconds
        self._thread = None
        self._stop_event = threading.Event()
        self._seen: Dict[Tuple, float] = {}
        self._snapshot_key: Tuple = tuple()

    def start(self) -> bool:
        if self._thread and self._thread.is_alive():
            return False
        self._stop_event.clear()
        self.state_store.set_monitor_running(True)
        self.state_store.append_monitor_log("Live monitor started.", phase="start")
        self._thread = threading.Thread(target=self._run, name="mac-sentinel-monitor", daemon=True)
        self._thread.start()
        return True

    def stop(self) -> bool:
        if not self._thread:
            return False
        self._stop_event.set()
        self.state_store.set_monitor_running(False)
        self.state_store.append_monitor_log("Live monitor stopping.", phase="stop")
        return True

    def _run(self) -> None:
        try:
            while not self._stop_event.is_set():
                activity = self.scan_service.collect_network_activity()
                connections = activity.get("connections", [])
                findings = activity.get("findings", [])
                self.state_store.update_monitor_cycle(len(connections))

                changed = self.state_store.set_monitor_connections(connections)
                snapshot_key = self._build_snapshot_key(connections)
                summary = (
                    f"Observed {len(connections)} active network flow(s); {len(findings)} rule-based risk event(s) in this cycle."
                )
                if snapshot_key != self._snapshot_key:
                    self._snapshot_key = snapshot_key
                    self.state_store.append_monitor_log(summary, phase="cycle")
                    self._append_connection_logs(connections)
                elif findings:
                    self.state_store.append_monitor_log(summary, phase="cycle")
                elif changed:
                    self.state_store.append_monitor_log(summary, phase="cycle")

                fresh_events = self._collect_new_events(findings)
                if fresh_events:
                    self.state_store.append_live_events(fresh_events)
                    for event in fresh_events:
                        location = event.get("remote_address") or event.get("matched_path") or event.get("launchd_label") or "unknown source"
                        self.state_store.append_monitor_log(
                            f"Flagged {event.get('title', 'risk event')} at {location}.",
                            level="warning",
                            phase="flagged",
                            extra={"finding_id": event.get("finding_id", "")},
                        )

                self._stop_event.wait(self.interval_seconds)
        except Exception as exc:
            self.state_store.fail_monitor(str(exc))
        finally:
            self.state_store.set_monitor_running(False)
            self.state_store.append_monitor_log("Live monitor stopped.", phase="stop")

    def _append_connection_logs(self, connections: List[Dict]) -> None:
        if not connections:
            self.state_store.append_monitor_log(
                "No active TCP/UDP connection entries were returned in this cycle.",
                level="warning",
                phase="observe",
            )
            return
        for conn in connections[:12]:
            service = f" [{conn.get('service_guess')}]" if conn.get('service_guess') else ''
            state = f" {conn.get('state')}" if conn.get('state') else ''
            message = (
                f"{conn.get('protocol', '')}{state} {conn.get('command', '')}[{conn.get('pid', '')}] "
                f"{conn.get('local_address', '')}:{conn.get('local_port', '')} -> "
                f"{conn.get('remote_address', '')}:{conn.get('remote_port', '')}{service}"
            )
            self.state_store.append_monitor_log(message, phase="observe")
        if len(connections) > 12:
            self.state_store.append_monitor_log(
                f"Omitted {len(connections) - 12} additional flow lines from this cycle to keep the UI readable.",
                phase="observe",
            )

    def _build_snapshot_key(self, connections: List[Dict]) -> Tuple:
        return tuple(sorted(
            (
                item.get('pid'), item.get('command'), item.get('protocol'), item.get('state'),
                item.get('local_address'), item.get('local_port'), item.get('remote_address'), item.get('remote_port')
            )
            for item in connections
        ))

    def _collect_new_events(self, snapshot: List[Dict]):
        now = time.time()
        fresh_events = []
        for event in snapshot:
            key = (
                event.get("rule_id"),
                event.get("matched_pid"),
                event.get("remote_address"),
                event.get("remote_port"),
                event.get("process_cmdline"),
            )
            last_seen = self._seen.get(key, 0.0)
            if now - last_seen < 45:
                continue
            self._seen[key] = now
            fresh_events.append(event)
        return fresh_events
