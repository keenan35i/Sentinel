import React, { useMemo, useState } from 'react';
import VirtualList from './VirtualList';

const severityRank = { high: 0, mid: 1, low: 2 };

export default function FindingsPanel({ title, findings, source, onOpen, onRemediate, onCopyPrompt }) {
  const [filter, setFilter] = useState('all');

  const filtered = useMemo(() => {
    const next = filter === 'all' ? findings : findings.filter((item) => item.threat_level === filter);
    return [...next].sort((a, b) => {
      const bySeverity = (severityRank[a.threat_level] ?? 99) - (severityRank[b.threat_level] ?? 99);
      if (bySeverity !== 0) return bySeverity;
      return (a.title || '').localeCompare(b.title || '');
    });
  }, [findings, filter]);

  return (
    <section className="card stack-gap-md findings-card">
      <div className="section-header findings-header">
        <div>
          <h2>{title}</h2>
          <p>{filtered.length} visible item(s)</p>
        </div>

        <div className="button-row wrap compact">
          <select value={filter} onChange={(event) => setFilter(event.target.value)}>
            <option value="all">All severities</option>
            <option value="high">High</option>
            <option value="mid">Mid</option>
            <option value="low">Low</option>
          </select>
          <button onClick={() => onCopyPrompt?.(title, filtered)} disabled={filtered.length === 0}>
            Copy review prompt
          </button>
        </div>
      </div>

      {filtered.length === 0 ? <div className="empty-state">No findings in this view.</div> : null}

      {filtered.length > 0 ? (
        <VirtualList
          items={filtered}
          estimatedItemHeight={250}
          maxHeight={520}
          itemClassName="virtual-row"
          renderItem={(item) => {
            const location = item.matched_path || item.launchd_label || item.remote_address || item.process_cmdline || 'No location captured';

            return (
              <article className="finding-item" key={item.finding_id}>
                <div className="finding-top">
                  <div className="finding-left">
                    <div className="finding-title-row">
                      <div className={`badge badge-${item.threat_level}`}>{item.threat_level}</div>
                      <div className="traffic-service">{item.confidence || 'context'}</div>
                      <h3>{item.title}</h3>
                    </div>
                    <p className="finding-family">{item.family}</p>
                  </div>

                  <div className="button-row wrap compact">
                    <button onClick={() => onOpen(source, item.finding_id)}>Open</button>
                    <button className="danger" onClick={() => onRemediate(source, item.finding_id)}>Remediate</button>
                  </div>
                </div>

                <p className="finding-desc">{item.description}</p>

                <div className="finding-meta-grid compact">
                  <Meta label="Location" value={location} />
                  <Meta label="Rule" value={item.rule_id} />
                  <Meta label="Actor" value={item.author_or_actor || 'Unknown'} />
                  <Meta label="Regex" value={item.matched_regex || '—'} />
                </div>
              </article>
            );
          }}
        />
      ) : null}
    </section>
  );
}

function Meta({ label, value }) {
  return (
    <div className="meta-block compact">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
