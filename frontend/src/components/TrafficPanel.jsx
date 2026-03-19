import React, { useMemo, useState } from 'react';
import VirtualList from './VirtualList';

function formatEndpoint(address, port) {
  if (!address) return '—';
  return port ? `${address}:${port}` : address;
}

function buildConnectionKey(item) {
  return [
    item.pid ?? 'nopid',
    item.fd || 'nofd',
    item.protocol || 'noprot',
    item.local_address || 'nolocal',
    item.local_port ?? '0',
    item.remote_address || 'noremote',
    item.remote_port ?? '0',
  ].join('|');
}

export default function TrafficPanel({ connections }) {
  const [showLoopback, setShowLoopback] = useState(false);
  const [protocolFilter, setProtocolFilter] = useState('all');

  const rows = useMemo(() => {
    let next = showLoopback ? connections : connections.filter((item) => !item.is_loopback);
    if (protocolFilter !== 'all') next = next.filter((item) => (item.protocol || '').toUpperCase() === protocolFilter);

    return [...next].sort((a, b) => {
      if ((a.protocol || '') !== (b.protocol || '')) {
        return (a.protocol || '').localeCompare(b.protocol || '');
      }
      return `${a.process_name || a.command || ''}`.localeCompare(`${b.process_name || b.command || ''}`);
    });
  }, [connections, protocolFilter, showLoopback]);

  return (
    <section className="card stack-gap-md traffic-card">
      <div className="section-header traffic-header">
        <div>
          <h2>Live traffic flows</h2>
          <p>Current machine-level connection details with process, ports, state, and service hints.</p>
        </div>

        <div className="button-row wrap compact">
          <select value={protocolFilter} onChange={(event) => setProtocolFilter(event.target.value)}>
            <option value="all">All protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
          </select>

          <label className="checkbox-chip">
            <input
              type="checkbox"
              checked={showLoopback}
              onChange={(event) => setShowLoopback(event.target.checked)}
            />
            <span>Show loopback</span>
          </label>
        </div>
      </div>

      {rows.length === 0 ? <div className="empty-state">No live connection rows in the current view.</div> : null}

      {rows.length > 0 ? (
        <VirtualList
          items={rows}
          estimatedItemHeight={170}
          maxHeight={460}
          itemClassName="virtual-row"
          getItemKey={buildConnectionKey}
          renderItem={(item) => (
            <article className="traffic-row" key={buildConnectionKey(item)}>
              <div className="traffic-main">
                <div className="traffic-title-row">
                  <div className={`badge badge-${(item.protocol || 'TCP').toLowerCase() === 'udp' ? 'low' : 'mid'}`}>
                    {item.protocol || 'NET'}
                  </div>
                  {item.state ? <div className="traffic-state">{item.state}</div> : null}
                  {item.service_guess ? <div className="traffic-service">{item.service_guess}</div> : null}
                </div>

                <div className="traffic-process">
                  {item.process_name || item.command || 'Unknown process'}{' '}
                  <span>PID {item.pid ?? '—'} · {item.user || 'unknown user'}</span>
                </div>

                <div className="traffic-flow">
                  {formatEndpoint(item.local_address, item.local_port)}
                  <span>→</span>
                  {formatEndpoint(item.remote_address, item.remote_port)}
                </div>

                <div className="traffic-cmdline">
                  {item.process_cmdline || item.raw_name || 'No command line captured'}
                </div>
              </div>

              <div className="traffic-side">
                <div><span>FD</span><strong>{item.fd || '—'}</strong></div>
                <div><span>Loopback</span><strong>{item.is_loopback ? 'Yes' : 'No'}</strong></div>
              </div>
            </article>
          )}
        />
      ) : null}
    </section>
  );
}
