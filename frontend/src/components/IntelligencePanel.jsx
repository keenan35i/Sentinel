import React from 'react';

export default function IntelligencePanel({ summary, artifacts, onImportArtifacts, onClearArtifacts, busy }) {
  const artifactCount = summary?.artifact_count || artifacts.length || 0;
  const loadedStix = summary?.loaded_stix_sets || 0;
  const byKind = Object.entries(summary?.artifacts_by_kind || {});

  return (
    <section className="card stack-gap-md">
      <div className="section-header">
        <div>
          <h2>Local forensic intake</h2>
          <p>Import Apple notifications, STIX files, iPhone backups, or sysdiagnose folders for offline-only review.</p>
        </div>
      </div>

      <div className="status-grid intelligence-grid">
        <Metric label="Artifacts" value={String(artifactCount)} tone={artifactCount ? 'info' : 'neutral'} />
        <Metric label="Loaded STIX sets" value={String(loadedStix)} tone={loadedStix ? 'good' : 'neutral'} />
        <Metric label="Findings" value={String(summary?.finding_count || 0)} tone={(summary?.finding_count || 0) ? 'warn' : 'neutral'} />
        <Metric label="Data flow" value={summary?.local_only ? 'Local only' : 'Unknown'} tone="good" />
      </div>

      <div className="button-row wrap compact">
        <button className="primary" onClick={onImportArtifacts} disabled={busy}>Import local artifacts</button>
        <button onClick={onClearArtifacts} disabled={busy || artifactCount === 0}>Clear imported artifacts</button>
      </div>

      {byKind.length > 0 ? (
        <div className="mini-list">
          {byKind.map(([kind, count]) => (
            <div className="mini-row" key={kind}>
              <span>{kind}</span>
              <strong>{count}</strong>
            </div>
          ))}
        </div>
      ) : (
        <div className="empty-state">No local forensic artifacts imported yet.</div>
      )}

      {artifacts.length > 0 ? (
        <div className="mini-list artifact-list">
          {artifacts.slice(0, 8).map((item) => (
            <div className="mini-row artifact-row" key={`${item.path}-${item.kind}`}>
              <span>{item.kind}</span>
              <strong>{item.name}</strong>
            </div>
          ))}
        </div>
      ) : null}
    </section>
  );
}

function Metric({ label, value, tone = 'neutral' }) {
  return (
    <div className={`status-pill tone-${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
