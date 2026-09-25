import type { Severity } from '../../types';

const severityMap: Record<Severity, string> = {
  Critical: 'severity-badge severity-badge--critical',
  High: 'severity-badge severity-badge--high',
  Medium: 'severity-badge severity-badge--medium',
  Low: 'severity-badge severity-badge--low',
  Informational: 'severity-badge severity-badge--informational',
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={severityMap[severity]}>{severity}</span>;
}
