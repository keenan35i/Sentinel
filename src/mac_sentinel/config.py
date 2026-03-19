import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    app_name: str = "Mac Sentinel"
    host: str = os.getenv("MAC_SENTINEL_HOST", "127.0.0.1")
    port: int = int(os.getenv("MAC_SENTINEL_PORT", "8765"))
    monitor_interval_seconds: int = int(os.getenv("MAC_SENTINEL_MONITOR_INTERVAL", "4"))
    max_recursive_matches_per_pattern: int = int(os.getenv("MAC_SENTINEL_MAX_MATCHES", "4000"))
    recursive_pattern_timeout_seconds: int = int(os.getenv("MAC_SENTINEL_PATTERN_TIMEOUT", "6"))
    default_max_findings_per_rule: int = int(os.getenv("MAC_SENTINEL_MAX_FINDINGS_PER_RULE", "50"))
    scan_log_retention: int = int(os.getenv("MAC_SENTINEL_SCAN_LOG_RETENTION", "1800"))
    monitor_log_retention: int = int(os.getenv("MAC_SENTINEL_MONITOR_LOG_RETENTION", "2200"))
    monitor_event_retention: int = int(os.getenv("MAC_SENTINEL_MONITOR_EVENT_RETENTION", "450"))
    monitor_connection_retention: int = int(os.getenv("MAC_SENTINEL_MONITOR_CONNECTION_RETENTION", "650"))
    intelligence_log_retention: int = int(os.getenv("MAC_SENTINEL_INTELLIGENCE_LOG_RETENTION", "600"))
    intelligence_finding_retention: int = int(os.getenv("MAC_SENTINEL_INTELLIGENCE_FINDING_RETENTION", "300"))
    intelligence_artifact_retention: int = int(os.getenv("MAC_SENTINEL_INTELLIGENCE_ARTIFACT_RETENTION", "80"))
    sse_wait_seconds: int = int(os.getenv("MAC_SENTINEL_SSE_WAIT_SECONDS", "20"))
    local_state_root: str = os.getenv("MAC_SENTINEL_STATE_DIR", "~/.mac_sentinel")

    @property
    def project_root(self) -> Path:
        return Path(__file__).resolve().parents[2]

    @property
    def data_dir(self) -> Path:
        return self.project_root / "data"

    @property
    def rules_path(self) -> Path:
        return self.data_dir / "ioc_patterns.json"

    @property
    def static_dir(self) -> Path:
        return Path(__file__).resolve().parent / "static"

    @property
    def local_state_dir(self) -> Path:
        root = Path(os.path.expanduser(self.local_state_root)).resolve()
        root.mkdir(parents=True, exist_ok=True)
        return root

    @property
    def local_db_path(self) -> Path:
        return self.local_state_dir / "mac_sentinel_local.db"


settings = Settings()
