import React from 'react';

export default function HeaderBar({ health, rulesMeta, backendUrl, packaged, streamMode = 'connecting' }) {
  const streamLabel = streamMode === 'live' ? 'Push updates' : streamMode === 'fallback' ? 'Fallback polling' : 'Connecting';
  const streamTone = streamMode === 'live' ? 'good' : streamMode === 'fallback' ? 'warn' : 'info';

  return (
    <header className="hero-card">
      <div>
        <div className="eyebrow">Local-first desktop security triage</div>
        <h1>Mac Sentinel</h1>
        <p className="hero-copy">
          Scan persistence, privacy-control abuse, provenance, trust changes, imported mobile forensics artifacts,
          and live network behavior without sending your data off-machine.
        </p>
      </div>
      <div className="hero-grid">
        <MetricTile label="Backend" value={health?.ok ? 'Online' : 'Starting'} tone={health?.ok ? 'good' : 'warn'} />
        <MetricTile label="Rules" value={String(rulesMeta?.rule_count || 0)} />
        <MetricTile label="Mode" value={packaged ? 'Packaged app' : 'Dev shell'} />
        <MetricTile label="Updates" value={streamLabel} tone={streamTone} />
        <MetricTile label="API" value={backendUrl.replace('http://', '')} />
      </div>
    </header>
  );
}

function MetricTile({ label, value, tone = 'neutral' }) {
  return (
    <div className={`metric-tile tone-${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
