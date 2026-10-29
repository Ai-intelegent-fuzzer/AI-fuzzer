const statusClassNames: Record<string, string> = {
  completed: 'status-badge status-badge--success',
  running: 'status-badge status-badge--running',
  failed: 'status-badge status-badge--danger',
  queued: 'status-badge status-badge--neutral',
  created: 'status-badge status-badge--neutral',
  paused: 'status-badge status-badge--warning',
  cancelled: 'status-badge status-badge--warning',
};

export function StatusBadge({ status }: { status: string }) {
  const label = status ? status[0].toUpperCase() + status.slice(1) : 'Unknown';
  return <span className={statusClassNames[status.toLowerCase()] ?? 'status-badge status-badge--neutral'}>{label}</span>;
}
