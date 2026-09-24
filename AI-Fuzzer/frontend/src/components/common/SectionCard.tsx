import type { ReactNode } from 'react';

interface SectionCardProps {
  title: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}

export function SectionCard({ title, subtitle, action, children, className = '' }: SectionCardProps) {
  return (
    <section className={`section-card ${className}`.trim()}>
      <div className="section-card__header">
        <div>
          <h2>{title}</h2>
          {subtitle ? <p>{subtitle}</p> : null}
        </div>
        {action ? <div className="section-card__action">{action}</div> : null}
      </div>
      {children}
    </section>
  );
}
