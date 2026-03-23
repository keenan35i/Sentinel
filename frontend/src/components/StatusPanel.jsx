import React from 'react';

export default function StatusPanel({ scanStatus, monitorStatus, protectionStatus, diagnostics, intelligenceSummary }) {
  const unreadable = (diagnostics?.permission_checks || []).filter((item) => item.exists && !item.readable).length;
  const intelCount = intelligenceSummary?.finding_count || 0;
  const protectionEvents = protectionStatus?.event_count || 0;
  return (
    <section className="card stack-gap-md">
      <div className="section-header">
        <div>
          <h2>Runtime status</h2>
          <p>Quick health view for scanning, monitoring, permissions, and imported forensic context.</p>
        </div>
      </div>
      <div className="status-grid status-grid-wide">
        <StatusPill title="Scan" value={scanStatus.running ? (scanStatus.paused ? 'Paused' : 'Running') : scanStatus.cancelled ? 'Cancelled' : 'Idle'} tone={scanStatus.running ? 'info' : scanStatus.error ? 'danger' : 'good'} />
        <StatusPill title="Progress" value={`${scanStatus.progress_percent || 0}%`} tone="neutral" />
        <StatusPill title="Monitor" value={monitorStatus.running ? 'Watching' : 'Stopped'} tone={monitorStatus.running ? 'good' : 'neutral'} />
        <StatusPill title="Active protection" value={protectionStatus?.running ? 'Protecting' : protectionStatus?.enabled ? 'Starting' : 'Off'} tone={protectionStatus?.running ? 'warn' : 'neutral'} />
        <StatusPill title="Protection events" value={String(protectionEvents)} tone={protectionEvents ? 'warn' : 'good'} />
        <StatusPill title="Protected paths blocked" value={String(unreadable)} tone={unreadable ? 'warn' : 'good'} />
        <StatusPill title="Imported intelligence findings" value={String(intelCount)} tone={intelCount ? 'warn' : 'neutral'} />
      </div>
      <div className="progress-shell">
        <div className="progress-label-row">
          <span>{scanStatus.current_rule || 'No active rule'}</span>
          <span>{scanStatus.scanned_rules || 0}/{scanStatus.total_rules || 0}</span>
        </div>
        <div className="progress-track">
          <div className="progress-fill" style={{ width: `${scanStatus.progress_percent || 0}%` }} />
        </div>
      </div>
      {scanStatus.error ? <div className="inline-alert danger">{scanStatus.error}</div> : null}
      {monitorStatus.error ? <div className="inline-alert danger">{monitorStatus.error}</div> : null}
      {protectionStatus?.error ? <div className="inline-alert danger">{protectionStatus.error}</div> : null}
    </section>
  );
}

function StatusPill({ title, value, tone }) {
  return (
    <div className={`status-pill tone-${tone}`}>
      <span>{title}</span>
      <strong>{value}</strong>
    </div>
  );
}
