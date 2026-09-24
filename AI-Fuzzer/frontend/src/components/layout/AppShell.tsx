import type { ReactNode } from 'react';
import { Activity, Bell, ShieldCheck } from 'lucide-react';
import { Sidebar } from './Sidebar';

interface AppShellProps {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  children: ReactNode;
}

export function AppShell({ title, subtitle, actions, children }: AppShellProps) {
  return (
    <div className="app-shell">
      <Sidebar />

      <div className="app-main">
        <header className="topbar">
          <div>
            <p className="eyebrow">Security operations</p>
            <h1>{title}</h1>
            {subtitle ? <p className="topbar-subtitle">{subtitle}</p> : null}
          </div>

          <div className="topbar-actions">
            <div className="status-chip status-chip--success" aria-live="polite">
              <Activity size={14} />
              <span>Scanner operational</span>
            </div>

            <button type="button" className="notification-btn" aria-label="Notifications">
              <Bell size={16} />
            </button>

            <div className="user-profile" aria-label="User profile">
              <div className="avatar-badge">
                <ShieldCheck size={14} />
              </div>
              <div>
                <strong>Sushil</strong>
                <small>Frontend Engineer</small>
              </div>
            </div>
          </div>
        </header>

        {actions ? <div className="page-actions">{actions}</div> : null}

        <main className="page-content">{children}</main>
      </div>
    </div>
  );
}
