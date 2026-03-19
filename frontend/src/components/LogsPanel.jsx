import React from 'react';
import VirtualList from './VirtualList';

export default function LogsPanel({ title, logs }) {
  const items = logs.slice().reverse();

  return (
    <section className="card stack-gap-md log-card">
      <div className="section-header">
        <div>
          <h2>{title}</h2>
          <p>Newest entries first. Rows are virtualized to keep the UI responsive.</p>
        </div>
      </div>

      {items.length === 0 ? <div className="empty-state">No log entries yet.</div> : null}

      {items.length > 0 ? (
        <VirtualList
          items={items}
          estimatedItemHeight={120}
          maxHeight={460}
          itemClassName="virtual-row"
          renderItem={(entry, index) => (
            <div className={`log-row level-${entry.level || 'info'}`} key={`${entry.timestamp}-${index}`}>
              <div className="log-time">{entry.timestamp}</div>
              <div className="log-phase">{entry.phase || 'event'}</div>
              <div className="log-message">{entry.message}</div>
            </div>
          )}
        />
      ) : null}
    </section>
  );
}