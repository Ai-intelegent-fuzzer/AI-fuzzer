import { useEffect, useState } from 'react';
import { ArrowLeft, ShieldAlert, ShieldCheck } from 'lucide-react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { ConfidenceBadge } from '../components/common/ConfidenceBadge';
import { EmptyState } from '../components/common/EmptyState';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { ApiError, getScanResults } from '../services/api';
import type { ApiFinding } from '../types';

export function FindingDetailPage() {
  const { findingId = '' } = useParams();
  const [searchParams] = useSearchParams();
  const scanId = searchParams.get('scanId') ?? '';
  const [finding, setFinding] = useState<ApiFinding | null>(null);
  const [loading, setLoading] = useState(Boolean(scanId));
  const [error, setError] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let active = true;
    if (!scanId) {
      return () => { active = false; };
    }

    getScanResults(scanId)
      .then((results) => {
        if (!active) return;
        const found = results.flatMap((result) => result.analysis.findings)
          .find((item) => item.finding_id === findingId);
        setFinding(found ?? null);
      })
      .catch((requestError: unknown) => {
        if (active) {
          setError(requestError instanceof ApiError ? requestError.message : 'Unable to load finding details.');
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => { active = false; };
  }, [findingId, refreshKey, scanId]);

  if (loading) {
    return <div className="page-loading">Loading finding evidence…</div>;
  }

  if (!scanId || !finding) {
    return (
      <EmptyState
        title={scanId ? 'Finding not found' : 'Scan ID required'}
        description={error || (scanId
          ? 'No matching finding was returned for this scan.'
          : 'Finding records are available only as part of a scan result. Open the finding from a loaded scan, or return to Findings and enter its scan ID.')}
        action={
          <div className="button-row">
            {scanId ? (
              <button type="button" className="primary-button" onClick={() => {
                setLoading(true);
                setError('');
                setRefreshKey((key) => key + 1);
              }} disabled={loading}>
                Retry
              </button>
            ) : null}
            <Link to="/findings" className="secondary-button">
              <ArrowLeft size={14} /> Back to findings
            </Link>
          </div>
        }
      />
    );
  }

  return (
    <div className="content-stack">
      <div className="detail-header">
        <div><div className="eyebrow">Analyzer evidence</div><h2>{finding.finding_id}</h2></div>
        <Link to="/findings" className="secondary-button"><ArrowLeft size={14} /> Back to findings</Link>
      </div>

      <section className="section-card">
        <div className="detail-summary-grid">
          <div><p className="muted-label">Finding</p><h3>{finding.title}</h3></div>
          <div><p className="muted-label">Severity</p><SeverityBadge severity={finding.severity} /></div>
          <div><p className="muted-label">Confidence</p><ConfidenceBadge confidence={finding.confidence} /></div>
          <div><p className="muted-label">Category</p><span>{finding.category}</span></div>
          <div><p className="muted-label">Target ID</p><span className="mono-text">{finding.target_id}</span></div>
          <div><p className="muted-label">Test ID</p><span className="mono-text">{finding.case_id}</span></div>
          <div><p className="muted-label">Timestamp</p><span>{new Date(finding.timestamp).toLocaleString()}</span></div>
        </div>
      </section>

      <section className="section-card">
        <div className="section-card__header"><div><h2>Detection rationale</h2><p>Evidence and rationale returned by the analyzer.</p></div></div>
        <div className="evidence-flow">
          {finding.detection_rationale ? (
            <div className="evidence-flow__step"><div className="evidence-flow__label">Rationale</div><div className="evidence-flow__value">{finding.detection_rationale}</div></div>
          ) : null}
          <div className="evidence-flow__step"><div className="evidence-flow__label">Evidence</div><pre className="evidence-flow__value">{finding.evidence}</pre></div>
          {finding.description ? (
            <div className="evidence-flow__step"><div className="evidence-flow__label">Description</div><div className="evidence-flow__value">{finding.description}</div></div>
          ) : null}
        </div>
      </section>

      <div className="two-column-grid">
        <section className="section-card">
          <div className="section-card__header"><div><h2>Expected behavior</h2><p>Reported reference behavior, when available.</p></div></div>
          <div className="detail-block">
            <div className="detail-block__icon"><ShieldCheck size={16} /></div>
            <p>{finding.expected_behavior || 'Not reported by the backend.'}</p>
          </div>
        </section>
        <section className="section-card">
          <div className="section-card__header"><div><h2>Observed behavior</h2><p>Reported observation, when available.</p></div></div>
          <div className="detail-block">
            <div className="detail-block__icon detail-block__icon--danger"><ShieldAlert size={16} /></div>
            <p>{finding.observed_behavior || 'Not reported by the backend.'}</p>
          </div>
        </section>
      </div>

      <section className="section-card">
        <div className="section-card__header"><div><h2>Recommended remediation</h2><p>Recommendation returned by the analyzer.</p></div></div>
        <div className="detail-block detail-block--stacked">
          <p>{finding.recommendation || 'No recommendation returned.'}</p>
        </div>
      </section>
    </div>
  );
}
