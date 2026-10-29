const confidenceClasses: Record<string, string> = {
  high: 'confidence-badge confidence-badge--high',
  medium: 'confidence-badge confidence-badge--medium',
  low: 'confidence-badge confidence-badge--low',
};

export function ConfidenceBadge({ confidence }: { confidence: string }) {
  const normalized = confidence.toLowerCase();
  const label = confidence ? confidence[0].toUpperCase() + confidence.slice(1) : 'Unknown';
  return <span className={confidenceClasses[normalized] ?? 'confidence-badge'}>{label}</span>;
}
