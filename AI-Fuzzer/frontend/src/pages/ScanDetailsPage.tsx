import { useEffect, useState } from 'react';
import { ArrowLeft, Clock3, Target as TargetIcon } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { EmptyState } from '../components/common/EmptyState';
import { StatusBadge } from '../components/common/StatusBadge';
import { ApiError, getScan, getScanResults } from '../services/api';
import type { ApiScanRecord, ApiScanResult } from '../types';

const activeStatuses = new Set(['created', 'queued', 'running', 'paused']);

function readableStatus(value: string): string {
  return value.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function displayDate(value: string | null): string {
  if (!value) return 'Not recorded';
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? 'Invalid timestamp returned'
    : date.toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' });
}

export function ScanDetailsPage() {
  const { scanId = '' } = useParams();
  const [scan, setScan] = useState<ApiScanRecord | null>(null);
  const [results, setResults] = useState<ApiScanResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;

    const load = async () => {
      try {
        const [scanResult, resultRows] = await Promise.all([
          getScan(scanId),
          getScanResults(scanId),
        ]);
        if (cancelled) return;
        setScan(scanResult);
        setResults(resultRows);
        setError('');
        if (activeStatuses.has(scanResult.status)) {
          timer = window.setTimeout(() => void load(), 4000);
        }
      } catch (requestError) {
        if (!cancelled) {
          setError(requestError instanceof ApiError ? requestError.message : 'Unable to load scan data.');
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    void load();

    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [scanId, refreshKey]);

  if (loading && !scan) {
    return <div className="page-loading">Loading scan record…</div>;
  }

  if (!scan) {
    return (
      <EmptyState
        title="Scan record unavailable"
        description={error || 'No scan data was returned for this ID.'}
        action={
          <div className="button-row">
            <button type="button" className="primary-button" onClick={() => {
              setLoading(true);
              setRefreshKey((key) => key + 1);
            }}>
              Retry
            </button>
            <Link to="/scans/history" className="secondary-button">
              <ArrowLeft size={14} /> Back to scan lookup
            </Link>
          </div>
        }
      />
    );
  }

  return (
    <div className="content-stack">
      {error ? <div className="inline-message inline-message--error" role="alert">{error}</div> : null}
      <div className="detail-header">
        <div>
          <div className="eyebrow">Backend scan record</div>
          <h2>{scan.scan_id}</h2>
        </div>
        <Link to="/scans/history" className="secondary-button">
          <ArrowLeft size={14} /> Back to scan lookup
        </Link>
      </div>

      <section className="section-card">
        <div className="detail-summary-grid">
          <div><p className="muted-label">Target ID</p><div className="inline-row"><TargetIcon size={14} /><span className="mono-text">{scan.target_id}</span></div></div>
          <div><p className="muted-label">Status</p><StatusBadge status={readableStatus(scan.status)} /></div>
          <div><p className="muted-label">Requested cases</p><span>{scan.requested_case_count}</span></div>
          <div><p className="muted-label">Generated cases</p><span>{scan.generated_case_count}</span></div>
          <div><p className="muted-label">Executed cases</p><span>{scan.executed_case_count}</span></div>
          <div><p className="muted-label">Findings</p><span>{scan.finding_count}</span></div>
        </div>
      </section>

      <div className="two-column-grid">
        <section className="section-card">
          <div className="section-card__header"><div><h2>Execution metadata</h2><p>Only values returned by the scan API are shown.</p></div></div>
          <div className="detail-list">
            <div><span>Created</span><strong>{displayDate(scan.created_at)}</strong></div>
            <div><span>Started</span><strong>{displayDate(scan.started_at)}</strong></div>
            <div><span>Completed</span><strong>{displayDate(scan.completed_at)}</strong></div>
            <div><span>Execution errors</span><strong>{scan.error_count}</strong></div>
            <div><span>Elapsed execution time</span><strong>{Math.round(scan.metrics.total_execution_time_ms)} ms</strong></div>
            <div><span>Categories tested</span><strong>{scan.metrics.categories_tested.join(', ') || 'Not reported'}</strong></div>
            {scan.failure_reason ? <div><span>Failure reason</span><strong>{scan.failure_reason}</strong></div> : null}
          </div>
        </section>

        <section className="section-card">
          <div className="section-card__header"><div><h2>Coverage</h2><p>Backend-reported scan metrics.</p></div></div>
          <div className="detail-list">
            <div><span>Unique test cases</span><strong>{scan.coverage.unique_test_cases}</strong></div>
            <div><span>Unique prompts</span><strong>{scan.coverage.unique_prompts}</strong></div>
            <div><span>Target responses</span><strong>{scan.coverage.target_responses}</strong></div>
            <div><span>Mutations generated</span><strong>{scan.metrics.mutations_generated}</strong></div>
            <div><span>Mutation strategies</span><strong>{scan.metrics.mutation_strategies_used.join(', ') || 'None reported'}</strong></div>
            <div><span>Retries</span><strong>{scan.metrics.retries}</strong></div>
          </div>
        </section>
      </div>

      <section className="section-card">
        <div className="section-card__header">
          <div><h2>Scan results</h2><p>Execution errors are displayed separately from analyzer verdicts.</p></div>
          {activeStatuses.has(scan.status) ? <span className="inline-row"><Clock3 size={14} /> Refreshing status every 4 seconds</span> : null}
        </div>
        {results.length === 0 ? (
          <EmptyState
            title={activeStatuses.has(scan.status) ? 'No results reported yet' : 'No result records returned'}
            description="The backend has not returned result rows for this scan."
          />
        ) : (
          <div className="content-stack">
            {results.map((result) => (
              <article className="evidence-panel" key={`${result.case.case_id}-${result.execution.status}`}>
                <div className="evidence-panel__header">
                  <span className="mono-text">{result.case.case_id}</span>
                  <span className={`status-badge status-badge--${result.analysis.status === 'fail' ? 'danger' : result.analysis.status === 'pass' ? 'success' : 'warning'}`}>
                    {readableStatus(result.analysis.status)}
                  </span>
                </div>
                <div className="detail-list">
                  <div><span>Category</span><strong>{result.analysis.category}</strong></div>
                  <div><span>Execution status</span><strong>{readableStatus(result.execution.status)}</strong></div>
                  <div><span>Provider / model</span><strong>{[result.execution.provider, result.execution.model].filter(Boolean).join(' / ') || 'Not reported'}</strong></div>
                  <div><span>Response time</span><strong>{result.execution.response_time_ms === null ? 'Not reported' : `${result.execution.response_time_ms} ms`}</strong></div>
                  {result.execution.failure_reason ? <div><span>Execution error</span><strong>{result.execution.failure_reason}</strong></div> : null}
                </div>
                {result.analysis.expected_behavior ? <p><strong>Expected:</strong> {result.analysis.expected_behavior}</p> : null}
                {result.analysis.observed_behavior ? <p><strong>Observed:</strong> {result.analysis.observed_behavior}</p> : null}
                {result.analysis.findings.map((finding) => (
                  <div className="detail-block detail-block--stacked" key={finding.finding_id}>
                    <div className="evidence-panel__header">
                      <strong>{finding.title}</strong>
                      <span className={`severity-badge severity-badge--${finding.severity.toLowerCase()}`}>{readableStatus(finding.severity)}</span>
                    </div>
                    <p>{finding.description || finding.detection_rationale || 'No description returned.'}</p>
                    <p><strong>Confidence:</strong> {readableStatus(finding.confidence)}</p>
                    <pre className="code-block">{finding.evidence}</pre>
                    <p><strong>Recommendation:</strong> {finding.recommendation}</p>
                  </div>
                ))}
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
