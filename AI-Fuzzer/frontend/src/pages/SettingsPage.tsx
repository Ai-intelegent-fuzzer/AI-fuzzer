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
              <p>Only approved targets can be selected for scan execution in this frontend demo. Internal policies are not enforced by the backend here.</p>
            </div>
          </div>

          <div className="settings-item">
            <div className="settings-item__icon"><SlidersHorizontal size={16} /></div>
            <div>
              <h3>Synthetic Leakage Testing</h3>
              <p>Leakage checks intentionally use demo-safe canaries such as CANARY-DEMO-7F3A and do not expose real credentials or personal data.</p>
            </div>
          </div>

          <div className="settings-item">
            <div className="settings-item__icon"><BellRing size={16} /></div>
            <div>
              <h3>Safe Demo Mode</h3>
              <p>All scan activity is simulated for review, evidence capture, and reporting workflows. No real attack automation is executed.</p>
            </div>
          </div>

          <div className="settings-item">
            <div className="settings-item__icon"><Lock size={16} /></div>
            <div>
              <h3>Operational Controls</h3>
              <p>Frontend safety guidance is limited to demonstration behavior and UI validation. Production enforcement belongs in the backend service layer.</p>
            </div>
          </div>
        </div>
      </SectionCard>
    </div>
  );
}
