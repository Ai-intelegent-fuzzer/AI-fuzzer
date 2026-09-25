interface ProgressBarProps {
  value: number;
  label: string;
}

export function ProgressBar({ value, label }: ProgressBarProps) {
  return (
    <div className="progress-block">
      <div className="progress-block__meta">
        <span>{label}</span>
        <strong>{value}%</strong>
      </div>
      <div className="progress-track" aria-label={`${label} progress`}>
        <div className="progress-fill" style={{ width: `${value}%` }} />
      </div>
    </div>
  );
}
