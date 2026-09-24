import type { ScanStatus } from '../../types';

const statusClassNames: Record<ScanStatus, string> = {
  Completed: 'status-badge status-badge--success',
  Running: 'status-badge status-badge--running',
  Failed: 'status-badge status-badge--danger',
  Queued: 'status-badge status-badge--neutral',
  Cancelled: 'status-badge status-badge--warning',
};

export function StatusBadge({ status }: { status: ScanStatus }) {
  return <span className={statusClassNames[status]}>{status}</span>;
}
