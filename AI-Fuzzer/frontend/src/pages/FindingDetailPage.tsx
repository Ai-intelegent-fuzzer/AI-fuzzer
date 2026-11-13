import { useEffect, useState } from 'react';
import { ArrowLeft, ShieldAlert, ShieldCheck } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { ConfidenceBadge } from '../components/common/ConfidenceBadge';
import { EmptyState } from '../components/common/EmptyState';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { apiClient } from '../services/api';
import type { Finding } from '../types';

export function FindingDetailPage() {
  const { findingId } = useParams();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [loadedFindingId, setLoadedFindingId] = useState('');
  const [error, setError] = useState('');
  const requestedFindingId = findingId ?? '';

  useEffect(() => {
    let active = true;
    apiClient.getFinding(requestedFindingId)
      .then((result) => {
        if (active) {
          setFinding(result);
          setError('');
        }
      })
      .catch((cause: unknown) => { if (active) setError(cause instanceof Error ? cause.message : 'Unable to load finding.'); })
      .finally(() => { if (active) setLoadedFindingId(requestedFindingId); });
    return () => { active = false; };
  }, [requestedFindingId]);

  if (loadedFindingId !== requestedFindingId) return <div className="page-loading">Loading evidence…</div>;
  if (!finding || finding.findingId !== requestedFindingId) {
    return (
      <EmptyState
        title="Finding not found"
        description={error || 'The backend did not return this finding.'}
        action={<Link to="/findings" className="primary-button"><ArrowLeft size={14} />Back to findings</Link>}
      />
    );
  }

  return (
    <div className="content-stack">
      <div className="detail-header">
        <div><div className="eyebrow">Evidence review</div><h2>{finding.findingId}</h2></div>
        <Link to="/findings" className="secondary-button"><ArrowLeft size={14} />Back to findings</Link>
      </div>

      <section className="section-card">
        <div className="detail-summary-grid">
          <div><p className="muted-label">Vulnerability Type</p><h3>{finding.vulnerabilityType}</h3></div>
          <div><p className="muted-label">Severity</p><SeverityBadge severity={finding.severity} /></div>
          <div><p className="muted-label">Confidence</p><ConfidenceBadge confidence={finding.confidence} /></div>
          <div><p className="muted-label">Risk score</p><strong>{finding.riskScore ?? 'Not calculated'}/100</strong></div>
          <div><p className="muted-label">Target</p><strong>{finding.targetName}</strong></div>
          <div><p className="muted-label">Test ID</p><span className="mono-text">{finding.testId}</span></div>
          <div><p className="muted-label">Analysis status</p><span>{finding.analysisStatus ?? finding.detectionResult}</span></div>
          <div><p className="muted-label">Timestamp</p><span>{new Date(finding.timestamp).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' })}</span></div>
          {finding.scanId ? <div><p className="muted-label">Originating scan</p><Link to={`/scans/${finding.scanId}`} className="inline-link mono-text">{finding.scanId}</Link></div> : null}
        </div>
      </section>

      <section className="section-card">
        <div className="section-card__header">
          <div><h2>Analyzer evidence</h2><p>Evidence and rationale returned for this finding.</p></div>
        </div>
        <div className="two-column-grid">
          <div className="detail-block">
            <div className="detail-block__icon"><ShieldCheck size={16} /></div>
            <div><strong>Expected behavior</strong><p>{finding.expectedBehavior}</p></div>
          </div>
          <div className="detail-block">
            <div className="detail-block__icon detail-block__icon--danger"><ShieldAlert size={16} /></div>
            <div><strong>Observed behavior</strong><p>{finding.actualBehavior}</p></div>
          </div>
        </div>
        <pre className="code-block">{finding.evidence}</pre>
      </section>

      <section className="section-card">
        <div className="section-card__header">
          <div><h2>Recommended remediation</h2><p>Advice returned by the analyzer for this finding.</p></div>
        </div>
        <div className="detail-block detail-block--stacked"><p>{finding.recommendation}</p></div>
      </section>
    </div>
  );
}
