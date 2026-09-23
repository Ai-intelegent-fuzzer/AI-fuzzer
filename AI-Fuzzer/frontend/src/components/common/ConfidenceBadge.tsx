import type { Confidence } from '../../types';

const confidenceMap: Record<Confidence, string> = {
  High: 'confidence-badge confidence-badge--high',
  Medium: 'confidence-badge confidence-badge--medium',
  Low: 'confidence-badge confidence-badge--low',
};

export function ConfidenceBadge({ confidence }: { confidence: Confidence }) {
  return <span className={confidenceMap[confidence]}>{confidence}</span>;
}
