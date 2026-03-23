function currentBaseUrl() {
  return window.macSentinel?.backendUrl || 'http://127.0.0.1:8765';
}

async function request(path, options = {}) {
  const response = await fetch(`${currentBaseUrl()}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    ...options,
  });

  if (!response.ok) {
    let detail = `Request failed: ${response.status}`;
    try {
      const payload = await response.json();
      detail = payload.detail || detail;
    } catch (_error) {
      // Keep the fallback message when a non-JSON error body is returned.
    }
    throw new Error(detail);
  }

  return response.json();
}

function createRevisionStream({ onRevisions, onError } = {}) {
  const stream = new EventSource(`${currentBaseUrl()}/api/events/stream`);
  stream.addEventListener('revisions', (event) => {
    try {
      const payload = JSON.parse(event.data || '{}');
      onRevisions?.(payload);
    } catch (error) {
      onError?.(error);
    }
  });
  stream.onerror = (error) => onError?.(error);
  return stream;
}

export const api = {
  currentBaseUrl,
  createRevisionStream,
  health: () => request('/api/health'),
  revisions: () => request('/api/revisions'),
  diagnostics: () => request('/api/diagnostics'),
  intelligenceSummary: () => request('/api/intelligence/summary'),
  intelligenceState: () => request('/api/intelligence/state'),
  intelligenceLogs: () => request('/api/intelligence/logs'),
  importArtifacts: (paths) => request('/api/intelligence/import', {
    method: 'POST',
    body: JSON.stringify({ paths }),
  }),
  clearIntelligence: () => request('/api/intelligence/state', { method: 'DELETE' }),
  scanStatus: () => request('/api/scan/status'),
  scanFindings: () => request('/api/scan/findings'),
  scanLogs: () => request('/api/scan/logs'),
  startScan: () => request('/api/scan/start', { method: 'POST' }),
  pauseScan: () => request('/api/scan/pause', { method: 'POST' }),
  resumeScan: () => request('/api/scan/resume', { method: 'POST' }),
  stopScan: () => request('/api/scan/stop', { method: 'POST' }),
  monitorStatus: () => request('/api/monitor/status'),
  monitorEvents: () => request('/api/monitor/events'),
  monitorConnections: () => request('/api/monitor/connections'),
  monitorLogs: () => request('/api/monitor/logs'),
  startMonitor: () => request('/api/monitor/start', { method: 'POST' }),
  stopMonitor: () => request('/api/monitor/stop', { method: 'POST' }),

  protectionStatus: () => request('/api/protection/status'),
  protectionEvents: () => request('/api/protection/events'),
  protectionLogs: () => request('/api/protection/logs'),
  enableProtection: () => request('/api/protection/enable', { method: 'POST' }),
  disableProtection: () => request('/api/protection/disable', { method: 'POST' }),
  rulesMetadata: () => request('/api/rules/metadata'),
  reloadRules: () => request('/api/rules/reload', { method: 'POST' }),
  openPermissionSettings: () => request('/api/permissions/open-full-disk-access', { method: 'POST' }),
  openFinding: (source, findingId) => request('/api/finding/open', {
    method: 'POST',
    body: JSON.stringify({ source, finding_id: findingId }),
  }),
  remediateFinding: (source, findingId) => request('/api/finding/remediate', {
    method: 'POST',
    body: JSON.stringify({ source, finding_id: findingId }),
  }),
};
