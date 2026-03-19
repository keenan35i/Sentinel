import React from 'react';

export default function ControlBar({
  scanStatus,
  monitorStatus,
  rulesMeta,
  onStartScan,
  onPauseScan,
  onResumeScan,
  onStopScan,
  onToggleMonitor,
  onReloadRules,
  onOpenPermissions,
}) {
  const monitorChecked = Boolean(monitorStatus.running);
  return (
    <section className="card stack-gap-md">
      <div className="section-header">
        <div>
          <h2>Controls</h2>
          <p>Run scans, toggle monitoring, reload rules, and jump to Full Disk Access.</p>
        </div>
      </div>
      <div className="control-grid">
        <div className="control-group">
          <span className="control-label">Scan actions</span>
          <div className="button-row wrap">
            <button className="primary" onClick={onStartScan} disabled={scanStatus.running}>Start full scan</button>
            <button onClick={onPauseScan} disabled={!scanStatus.running || scanStatus.paused}>Pause</button>
            <button onClick={onResumeScan} disabled={!scanStatus.running || !scanStatus.paused}>Resume</button>
            <button className="danger" onClick={onStopScan} disabled={!scanStatus.running}>Stop</button>
          </div>
        </div>
        <div className="control-group">
          <span className="control-label">Live monitor</span>
          <label className="toggle-row">
            <input type="checkbox" checked={monitorChecked} onChange={(event) => onToggleMonitor(event.target.checked)} />
            <span className="toggle-slider" />
            <span>{monitorChecked ? 'Monitoring network activity' : 'Monitoring is off'}</span>
          </label>
        </div>
        <div className="control-group">
          <span className="control-label">Rules & permissions</span>
          <div className="button-row wrap">
            <button onClick={onReloadRules}>Reload rules ({rulesMeta?.rule_count || 0})</button>
            <button onClick={onOpenPermissions}>Open Full Disk Access</button>
          </div>
        </div>
      </div>
    </section>
  );
}
