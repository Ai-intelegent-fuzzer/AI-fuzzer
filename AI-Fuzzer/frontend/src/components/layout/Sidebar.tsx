import { BarChart3, FileText, Flag, History, LayoutDashboard, PlusCircle, Settings, Shield, Target } from 'lucide-react';
import { NavLink } from 'react-router-dom';

const navItems = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/targets', label: 'Targets', icon: Target },
  { to: '/scans/new', label: 'New Scan', icon: PlusCircle },
  { to: '/scans/history', label: 'Scan History', icon: History },
  { to: '/findings', label: 'Findings', icon: Flag },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/settings', label: 'Settings', icon: Settings },
];

export function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="brand-block">
        <div className="brand-mark" aria-hidden="true">
          <Shield size={18} />
        </div>
        <div>
          <div className="brand-name">AI-Fuzzer</div>
          <div className="brand-subtitle">AI Security Testing Platform</div>
        </div>
      </div>

      <nav className="sidebar-nav" aria-label="Main navigation">
        {navItems.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/dashboard'}
            className={({ isActive }: { isActive: boolean }) =>
              `nav-item ${isActive ? 'nav-item--active' : ''}`
            }
          >
            <Icon size={16} />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="mini-panel">
          <div className="mini-panel__label">Threat posture</div>
          <div className="mini-panel__value">Elevated</div>
        </div>
        <div className="mini-panel mini-panel--muted">
          <BarChart3 size={14} />
          <span>Live assessment</span>
        </div>
      </div>
    </aside>
  );
}
