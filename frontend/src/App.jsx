import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api } from './api';
import HeaderBar from './components/HeaderBar';
import StatusPanel from './components/StatusPanel';
import ControlBar from './components/ControlBar';
import DiagnosticsPanel from './components/DiagnosticsPanel';
import FindingsPanel from './components/FindingsPanel';
import LogsPanel from './components/LogsPanel';
import TrafficPanel from './components/TrafficPanel';
import IntelligencePanel from './components/IntelligencePanel';

const FALLBACK_POLL_MS = 10000;

function buildReviewPrompt(panelTitle, findings) {
  const header = [
    'Please review these Mac security scanner findings and tell me which look like legitimate threats versus likely false positives.',
    'Be skeptical of detections caused by development repos, packaged app assets, vendor libraries, browser extensions, scanner rule files, or normal macOS/Chrome files.',
    'For each item, explain why it looks real or why it is probably noise.',
    `Panel: ${panelTitle}`,
    `Finding count: ${findings.length}`,
    '',
    'Findings:',
  ];

  const body = findings.map((item, index) => {
    const location = item.matched_path || item.launchd_label || item.remote_address || item.process_cmdline || 'No location captured';
    return [
      `${index + 1}. ${item.title}`,
      `   Severity: ${item.threat_level}`,
      `   Confidence: ${item.confidence || 'unknown'}`,
      `   Rule ID: ${item.rule_id}`,
      `   Family: ${item.family}`,
      `   Location: ${location}`,
      `   Evidence Type: ${item.evidence_type}`,
      `   Matched Regex: ${item.matched_regex || '—'}`,
      `   Actor/Author: ${item.author_or_actor || 'Unknown'}`,
      `   Description: ${item.description}`,
    ].join('\n');
  });

  return [...header, ...body].join('\n');
}

async function copyText(text) {
  if (navigator?.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const el = document.createElement('textarea');
  el.value = text;
  el.style.position = 'fixed';
  el.style.opacity = '0';
  document.body.appendChild(el);
  el.focus();
  el.select();
  document.execCommand('copy');
  document.body.removeChild(el);
}

export default function App() {
  const [health, setHealth] = useState(null);
  const [diagnostics, setDiagnostics] = useState(null);
  const [rulesMeta, setRulesMeta] = useState(null);
  const [scanStatus, setScanStatus] = useState({});
  const [scanFindings, setScanFindings] = useState([]);
  const [scanLogs, setScanLogs] = useState([]);
  const [monitorStatus, setMonitorStatus] = useState({});
  const [monitorEvents, setMonitorEvents] = useState([]);
  const [monitorConnections, setMonitorConnections] = useState([]);
  const [monitorLogs, setMonitorLogs] = useState([]);
  const [protectionStatus, setProtectionStatus] = useState({});
  const [protectionEvents, setProtectionEvents] = useState([]);
  const [protectionLogs, setProtectionLogs] = useState([]);
  const [intelArtifacts, setIntelArtifacts] = useState([]);
  const [intelFindings, setIntelFindings] = useState([]);
  const [intelLogs, setIntelLogs] = useState([]);
  const [intelSummary, setIntelSummary] = useState({});
  const [toast, setToast] = useState(null);
  const [appInfo, setAppInfo] = useState(null);
  const [artifactBusy, setArtifactBusy] = useState(false);
  const [streamMode, setStreamMode] = useState('connecting');

  const revisionsRef = useRef(null);
  const refreshInFlight = useRef(false);
  const fallbackTimerRef = useRef(null);
  const streamRef = useRef(null);

  const showToast = useCallback((message, tone = 'info') => {
    setToast({ message, tone, id: Date.now() });
  }, []);

  const loadStatic = useCallback(async () => {
    const [healthData, diagData, rulesData] = await Promise.all([
      api.health(),
      api.diagnostics(),
      api.rulesMetadata(),
    ]);
    setHealth(healthData);
    setDiagnostics(diagData);
    setRulesMeta(rulesData);
  }, []);

  const loadDynamicAll = useCallback(async () => {
    const [revisions, nextScanStatus, nextScanFindings, nextScanLogs, nextMonitorStatus, nextMonitorEvents, nextMonitorConnections, nextMonitorLogs, nextProtectionStatus, nextProtectionEvents, nextProtectionLogs, nextIntelState, nextIntelLogs] = await Promise.all([
      api.revisions(),
      api.scanStatus(),
      api.scanFindings(),
      api.scanLogs(),
      api.monitorStatus(),
      api.monitorEvents(),
      api.monitorConnections(),
      api.monitorLogs(),
      api.protectionStatus(),
      api.protectionEvents(),
      api.protectionLogs(),
      api.intelligenceState(),
      api.intelligenceLogs(),
    ]);
    revisionsRef.current = revisions;
    setScanStatus(nextScanStatus);
    setScanFindings(nextScanFindings.findings || []);
    setScanLogs(nextScanLogs.logs || []);
    setMonitorStatus(nextMonitorStatus);
    setMonitorEvents(nextMonitorEvents.findings || []);
    setMonitorConnections(nextMonitorConnections.connections || []);
    setMonitorLogs(nextMonitorLogs.logs || []);
    setProtectionStatus(nextProtectionStatus);
    setProtectionEvents(nextProtectionEvents.findings || []);
    setProtectionLogs(nextProtectionLogs.logs || []);
    setIntelArtifacts(nextIntelState.artifacts || []);
    setIntelFindings(nextIntelState.findings || []);
    setIntelSummary(nextIntelState.summary || {});
    setIntelLogs(nextIntelLogs.logs || []);
  }, []);

  const refreshChanges = useCallback(async (force = false, incomingRevisions = null) => {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    try {
      const nextRevisions = incomingRevisions || await api.revisions();
      const prev = revisionsRef.current;
      const firstLoad = !prev || force;
      const changedKeys = firstLoad
        ? ['scan_status', 'scan_findings', 'scan_logs', 'monitor_status', 'monitor_events', 'monitor_connections', 'monitor_logs', 'protection_status', 'protection_events', 'protection_logs', 'intelligence_findings', 'intelligence_artifacts', 'intelligence_logs', 'intelligence_summary']
        : Object.keys(nextRevisions).filter((key) => nextRevisions[key] !== prev[key]);

      if (changedKeys.length === 0) {
        revisionsRef.current = nextRevisions;
        return;
      }

      const tasks = [];
      const apply = [];
      const maybeFetch = (keys, fn, setter, pick) => {
        const changed = keys.some((key) => changedKeys.includes(key));
        if (!changed) return;
        tasks.push(fn());
        apply.push((payload) => setter(pick ? pick(payload) : payload));
      };

      maybeFetch(['scan_status'], api.scanStatus, setScanStatus);
      maybeFetch(['scan_findings'], api.scanFindings, setScanFindings, (payload) => payload.findings || []);
      maybeFetch(['scan_logs'], api.scanLogs, setScanLogs, (payload) => payload.logs || []);
      maybeFetch(['monitor_status'], api.monitorStatus, setMonitorStatus);
      maybeFetch(['monitor_events'], api.monitorEvents, setMonitorEvents, (payload) => payload.findings || []);
      maybeFetch(['monitor_connections'], api.monitorConnections, setMonitorConnections, (payload) => payload.connections || []);
      maybeFetch(['monitor_logs'], api.monitorLogs, setMonitorLogs, (payload) => payload.logs || []);
      maybeFetch(['protection_status'], api.protectionStatus, setProtectionStatus);
      maybeFetch(['protection_events'], api.protectionEvents, setProtectionEvents, (payload) => payload.findings || []);
      maybeFetch(['protection_logs'], api.protectionLogs, setProtectionLogs, (payload) => payload.logs || []);
      maybeFetch(['intelligence_findings', 'intelligence_artifacts', 'intelligence_summary'], api.intelligenceState, (payload) => {
        setIntelArtifacts(payload.artifacts || []);
        setIntelFindings(payload.findings || []);
        setIntelSummary(payload.summary || {});
      });
      maybeFetch(['intelligence_logs'], api.intelligenceLogs, setIntelLogs, (payload) => payload.logs || []);

      const results = await Promise.all(tasks);
      results.forEach((payload, index) => apply[index](payload));
      revisionsRef.current = nextRevisions;
    } catch (error) {
      showToast(error.message || 'Could not refresh the app state.', 'danger');
    } finally {
      refreshInFlight.current = false;
    }
  }, [showToast]);

  useEffect(() => {
    let cancelled = false;
    const boot = async () => {
      try {
        await loadStatic();
        await loadDynamicAll();
      } catch (error) {
        if (!cancelled) showToast(error.message || 'Could not start the app.', 'danger');
      }
    };
    boot();
    return () => {
      cancelled = true;
    };
  }, [loadDynamicAll, loadStatic, showToast]);

  useEffect(() => {
    window.macSentinel?.getAppInfo?.().then(setAppInfo).catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!toast) return undefined;
    const timer = setTimeout(() => setToast(null), 3200);
    return () => clearTimeout(timer);
  }, [toast]);

  useEffect(() => {
    const startFallbackPoll = () => {
      if (fallbackTimerRef.current) return;
      fallbackTimerRef.current = setInterval(() => {
        if (document.hidden) return;
        refreshChanges(false);
      }, FALLBACK_POLL_MS);
    };

    const stopFallbackPoll = () => {
      if (!fallbackTimerRef.current) return;
      clearInterval(fallbackTimerRef.current);
      fallbackTimerRef.current = null;
    };

    const stream = api.createRevisionStream({
      onRevisions: ({ revisions }) => {
        setStreamMode('live');
        stopFallbackPoll();
        refreshChanges(false, revisions || null);
      },
      onError: () => {
        setStreamMode('fallback');
        startFallbackPoll();
      },
    });

    streamRef.current = stream;

    return () => {
      stopFallbackPoll();
      streamRef.current?.close?.();
    };
  }, [refreshChanges]);

  const backendUrl = useMemo(() => appInfo?.backendUrl || api.currentBaseUrl(), [appInfo]);

  const runAction = useCallback(async (fn, successMessage) => {
    try {
      const result = await fn();
      if (successMessage) showToast(successMessage, 'good');
      if (result?.actions?.length) showToast(result.actions.join(' · '), 'info');
      await refreshChanges(true);
    } catch (error) {
      showToast(error.message || 'Action failed.', 'danger');
    }
  }, [refreshChanges, showToast]);

  const handleCopyPrompt = useCallback(async (panelTitle, findings) => {
    try {
      await copyText(buildReviewPrompt(panelTitle, findings));
      showToast(`Copied ${findings.length} finding(s) as a review prompt.`, 'good');
    } catch (error) {
      showToast(error.message || 'Could not copy the review prompt.', 'danger');
    }
  }, [showToast]);

  const handleImportArtifacts = useCallback(async () => {
    try {
      setArtifactBusy(true);
      const selected = await window.macSentinel?.chooseArtifacts?.({
        properties: ['openFile', 'openDirectory', 'multiSelections'],
        title: 'Choose Apple notifications, STIX files, backups, or sysdiagnose folders',
      });
      if (!selected || selected.length === 0) return;
      const result = await api.importArtifacts(selected);
      showToast(`Imported ${result.imported_count} artifact(s) and found ${result.finding_count} intelligence item(s).`, result.finding_count ? 'warn' : 'good');
      await refreshChanges(true);
    } catch (error) {
      showToast(error.message || 'Could not import local artifacts.', 'danger');
    } finally {
      setArtifactBusy(false);
    }
  }, [refreshChanges, showToast]);

  return (
    <div className="app-shell">
      <div className="app-frame">
        <HeaderBar
          health={health}
          rulesMeta={rulesMeta}
          backendUrl={backendUrl}
          packaged={Boolean(appInfo?.isPackaged)}
          streamMode={streamMode}
        />
        <div className="main-grid">
          <div className="column column-main">
            <StatusPanel scanStatus={scanStatus} monitorStatus={monitorStatus} protectionStatus={protectionStatus} diagnostics={diagnostics} intelligenceSummary={intelSummary} />
            <ControlBar
              scanStatus={scanStatus}
              monitorStatus={monitorStatus}
              protectionStatus={protectionStatus}
              rulesMeta={rulesMeta}
              onStartScan={() => runAction(() => api.startScan(), 'Full scan started')}
              onPauseScan={() => runAction(() => api.pauseScan(), 'Scan paused')}
              onResumeScan={() => runAction(() => api.resumeScan(), 'Scan resumed')}
              onStopScan={() => runAction(() => api.stopScan(), 'Scan stop requested')}
              onToggleMonitor={(checked) => runAction(() => checked ? api.startMonitor() : api.stopMonitor(), checked ? 'Live monitor started' : 'Live monitor stopped')}
              onToggleProtection={(checked) => runAction(() => checked ? api.enableProtection() : api.disableProtection(), checked ? 'Active protection enabled' : 'Active protection disabled')}
              onReloadRules={() => runAction(() => api.reloadRules(), 'Rules reloaded')}
              onOpenPermissions={() => runAction(() => api.openPermissionSettings(), 'Opened Full Disk Access settings')}
            />
            <FindingsPanel
              title="Active protection events"
              findings={protectionEvents}
              source="protect"
              onCopyPrompt={handleCopyPrompt}
              onOpen={(source, id) => runAction(() => api.openFinding(source, id))}
              onRemediate={(source, id) => runAction(() => api.remediateFinding(source, id), 'Remediation requested')}
            />
            <IntelligencePanel
              summary={intelSummary}
              artifacts={intelArtifacts}
              busy={artifactBusy}
              onImportArtifacts={handleImportArtifacts}
              onClearArtifacts={() => runAction(() => api.clearIntelligence(), 'Cleared imported local artifacts')}
            />
            <DiagnosticsPanel diagnostics={diagnostics} />
            <TrafficPanel connections={monitorConnections} />
            <FindingsPanel
              title="Imported intelligence findings"
              findings={intelFindings}
              source="intel"
              onCopyPrompt={handleCopyPrompt}
              onOpen={(source, id) => runAction(() => api.openFinding(source, id))}
              onRemediate={(source, id) => runAction(() => api.remediateFinding(source, id), 'Remediation requested')}
            />
            <FindingsPanel
              title="Scan findings"
              findings={scanFindings}
              source="scan"
              onCopyPrompt={handleCopyPrompt}
              onOpen={(source, id) => runAction(() => api.openFinding(source, id))}
              onRemediate={(source, id) => runAction(() => api.remediateFinding(source, id), 'Remediation requested')}
            />
            <FindingsPanel
              title="Live monitor findings"
              findings={monitorEvents}
              source="live"
              onCopyPrompt={handleCopyPrompt}
              onOpen={(source, id) => runAction(() => api.openFinding(source, id))}
              onRemediate={(source, id) => runAction(() => api.remediateFinding(source, id), 'Remediation requested')}
            />
          </div>
          <div className="column column-side">
            <LogsPanel title="Scan log" logs={scanLogs} />
            <LogsPanel title="Imported intelligence log" logs={intelLogs} />
            <LogsPanel title="Live monitor log" logs={monitorLogs} />
            <LogsPanel title="Active protection log" logs={protectionLogs} />
          </div>
        </div>
      </div>
      {toast ? <div className={`toast tone-${toast.tone}`}>{toast.message}</div> : null}
    </div>
  );
}
