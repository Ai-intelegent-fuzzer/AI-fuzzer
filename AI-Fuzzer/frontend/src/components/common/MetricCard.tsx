import type { ReactNode } from 'react';

interface MetricCardProps {
  icon: ReactNode;
  label: string;
  value: string;
  detail: string;
  tone?: 'default' | 'success' | 'warning' | 'danger';
}

export function MetricCard({ icon, label, value, detail, tone = 'default' }: MetricCardProps) {
  return (
    <article className={`metric-card metric-card--${tone}`}>
      <div className="metric-card__icon">{icon}</div>
      <div className="metric-card__content">
        <div className="metric-card__label">{label}</div>
        <div className="metric-card__value">{value}</div>
        <div className="metric-card__detail">{detail}</div>
      </div>
    </article>
  );
}
