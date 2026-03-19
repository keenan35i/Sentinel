import React from 'react';

export default function DiagnosticsPanel({ diagnostics }) {
  const commands = Object.entries(diagnostics?.commands || {});
  const advanced = diagnostics?.advanced_checks || {};
  const profileInventory = advanced.profile_inventory || {};
  const tccAudit = advanced.tcc_audit || {};
  const downloads = advanced.download_security || {};
  const trustSettings = advanced.trust_settings || {};

  return (
    <section className="card stack-gap-md">
      <div className="section-header">
        <div>
          <h2>Diagnostics</h2>
          <p>Validate command availability, protected-path access, and conservative host-intelligence context.</p>
        </div>
      </div>
      <div className="diag-grid diag-grid-expanded">
        <div className="diag-column">
          <h3>Commands</h3>
          <div className="mini-list">
            {commands.map(([name, info]) => (
              <div className="mini-row" key={name}>
                <span>{name}</span>
                <strong className={info.available ? 'text-good' : 'text-warn'}>{info.available ? 'Found' : 'Missing'}</strong>
              </div>
            ))}
          </div>
        </div>
        <div className="diag-column">
          <h3>Protected paths</h3>
          <div className="mini-list">
            {(diagnostics?.permission_checks || []).map((item) => (
              <div className="mini-row" key={item.path}>
                <span>{item.name}</span>
                <strong className={item.readable ? 'text-good' : item.exists ? 'text-warn' : 'text-muted'}>
                  {item.readable ? 'Readable' : item.exists ? 'Blocked' : 'Missing'}
                </strong>
              </div>
            ))}
          </div>
        </div>
        <div className="diag-column">
          <h3>Advanced host checks</h3>
          <div className="mini-list">
            <div className="mini-row"><span>Sensitive installed profiles</span><strong>{profileInventory.profiles_with_sensitive_payloads || 0}</strong></div>
            <div className="mini-row"><span>Suspicious TCC grants</span><strong>{tccAudit.suspicious_grants || 0}</strong></div>
            <div className="mini-row"><span>Downloaded candidates</span><strong>{downloads.suspicious_candidates || 0}</strong></div>
            <div className="mini-row"><span>Custom trust settings</span><strong>{trustSettings.user_has_custom_settings || trustSettings.admin_has_custom_settings ? 'Present' : 'None seen'}</strong></div>
          </div>
        </div>
      </div>
      <div className="diag-notes">
        {(diagnostics?.recommendations || []).map((note) => (
          <div className="inline-alert" key={note}>{note}</div>
        ))}
        {(advanced?.notes || []).map((note) => (
          <div className="inline-alert" key={note}>{note}</div>
        ))}
      </div>
    </section>
  );
}
