from __future__ import annotations

import uvicorn
from fastapi import FastAPI

from .api.routes import build_router
from .config import settings
from .core.active_protection import ActiveProtectionService
from .core.diagnostics import DiagnosticsService
from .core.forensics import LocalArtifactIntelligenceService
from .core.host_intelligence import HostIntelligenceService
from .core.local_storage import LocalStorage
from .core.monitor import MonitorService
from .core.remediation import RemediationService
from .core.rules import RuleRepository
from .core.runtime import RuntimeCollector
from .core.scanner import ScanService
from .core.state import AppStateStore


def create_application() -> FastAPI:
    storage = LocalStorage(settings.local_db_path)
    collector = RuntimeCollector()
    state = AppStateStore(storage=storage)
    rules = RuleRepository(settings.rules_path)
    intelligence = HostIntelligenceService(collector=collector, storage=storage)
    forensic_intelligence = LocalArtifactIntelligenceService(state_store=state, collector=collector)
    scanner = ScanService(
        collector=collector,
        rule_repository=rules,
        state_store=state,
        intelligence=intelligence,
    )
    monitor = MonitorService(scan_service=scanner, state_store=state, interval_seconds=settings.monitor_interval_seconds)
    remediation = RemediationService()
    protection = ActiveProtectionService(collector=collector, scan_service=scanner, state_store=state, remediation=remediation, storage=storage, interval_seconds=settings.active_protection_interval_seconds)
    diagnostics = DiagnosticsService(collector=collector, intelligence=intelligence)

    services = {
        'rules': rules,
        'state': state,
        'scanner': scanner,
        'monitor': monitor,
        'remediation': remediation,
        'protection': protection,
        'diagnostics': diagnostics,
        'intelligence': intelligence,
        'forensics': forensic_intelligence,
    }

    app = FastAPI(title=settings.app_name)
    app.state.services = services

    @app.get('/', include_in_schema=False)
    def root():
        return {'ok': True, 'service': settings.app_name, 'api': '/api'}

    app.include_router(build_router(services), prefix='/api')
    return app


app = create_application()


def start() -> None:
    uvicorn.run(
        'src.mac_sentinel.main:app',
        host=settings.host,
        port=settings.port,
        reload=False,
        log_level='info',
    )
