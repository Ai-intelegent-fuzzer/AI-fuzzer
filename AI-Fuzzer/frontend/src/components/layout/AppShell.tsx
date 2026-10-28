import type { ReactNode } from 'react';
import { Activity, Shield } from 'lucide-react';
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
            <div className="status-chip" aria-live="polite">
              <Activity size={14} />
              <span>Read-only client</span>
            </div>

            <div className="user-profile" aria-label="Authentication status">
              <div className="avatar-badge">
                <Shield size={14} />
              </div>
              <div>
                <strong>Local UI</strong>
                <small>Authentication not configured</small>
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
