import { BellRing, Lock, ShieldCheck, SlidersHorizontal } from 'lucide-react';
import { SectionCard } from '../components/common/SectionCard';

export function SettingsPage() {
  return (
    <div className="content-stack">
      <SectionCard title="Platform Settings" subtitle="Operational preferences and security controls">
        <div className="settings-grid">
          <div className="settings-item">
            <div className="settings-item__icon"><ShieldCheck size={16} /></div>
            <div>
              <h3>Authorized Targets Only</h3>
              <p>Targets must be registered and authorization must be explicitly confirmed before connectivity checks or scans. Remote endpoints are subject to backend HTTPS, host, and address validation.</p>
            </div>
          </div>

          <div className="settings-item">
            <div className="settings-item__icon"><SlidersHorizontal size={16} /></div>
            <div>
              <h3>Heuristic Response Analysis</h3>
              <p>Findings are based on category-scoped behavioral indicators in actual model responses. Review evidence and confidence before treating a heuristic as a confirmed security issue.</p>
            </div>
          </div>

          <div className="settings-item">
            <div className="settings-item__icon"><BellRing size={16} /></div>
            <div>
              <h3>Provider Credentials</h3>
              <p>Credentials are sent to the backend for encrypted storage and are not returned by target APIs. Configure the encryption key before saving provider credentials.</p>
            </div>
          </div>

          <div className="settings-item">
            <div className="settings-item__icon"><Lock size={16} /></div>
            <div>
              <h3>Persistence and Reports</h3>
              <p>Scans, executions, findings, and generated reports are stored in the configured SQLite database. Reports describe only executed tests and do not prove a target is secure.</p>
            </div>
          </div>
        </div>
      </SectionCard>
    </div>
  );
}
