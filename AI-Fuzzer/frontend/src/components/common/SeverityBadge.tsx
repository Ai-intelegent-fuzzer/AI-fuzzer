const severityClasses: Record<string, string> = {
  critical: 'severity-badge severity-badge--critical',
  high: 'severity-badge severity-badge--high',
  medium: 'severity-badge severity-badge--medium',
  low: 'severity-badge severity-badge--low',
  informational: 'severity-badge severity-badge--informational',
};

export function SeverityBadge({ severity }: { severity: string }) {
  const normalized = severity.toLowerCase();
  const label = severity ? severity[0].toUpperCase() + severity.slice(1) : 'Unknown';
  return <span className={severityClasses[normalized] ?? 'severity-badge'}>{label}</span>;
}
