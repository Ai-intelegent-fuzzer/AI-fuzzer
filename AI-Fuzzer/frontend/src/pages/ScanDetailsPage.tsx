import { useCallback, useEffect, useState } from 'react';
import { ArrowLeft, Clock3, Gauge, Target as TargetIcon } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { EmptyState } from '../components/common/EmptyState';
import { StatusBadge } from '../components/common/StatusBadge';
import { apiClient } from '../services/api';
import type { ApiScanResult, Finding, Scan } from '../types';

const activeStatuses = new Set<Scan['status']>(['Queued', 'Running']);

export function ScanDetailsPage() {
  const { scanId } = useParams();
  const [scan, setScan] = useState<Scan | null>(null);
  const [results, setResults] = useState<ApiScanResult[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loadedScanId, setLoadedScanId] = useState('');
  const [error, setError] = useState('');
  const [isCancelling, setIsCancelling] = useState(false);

  const refresh = useCallback(async () => {
    if (!scanId) return;
    const [scanRecord, scanResults, scanFindings] = await Promise.all([
      apiClient.getScan(scanId),
      apiClient.getScanResults(scanId),
      apiClient.getScanFindings(scanId),
    ]);
    setScan(scanRecord);
    setResults(scanResults);
    setFindings(scanFindings);
    setError('');
  }, [scanId]);
  const requestedScanId = scanId ?? '';
  const scanStatus = scan?.status;

  useEffect(() => {
    let active = true;
    Promise.all([
      apiClient.getScan(requestedScanId),
      apiClient.getScanResults(requestedScanId),
      apiClient.getScanFindings(requestedScanId),
    ])
      .then(([scanRecord, scanResults, scanFindings]) => {
        if (!active) return;
        setScan(scanRecord);
        setResults(scanResults);
        setFindings(scanFindings);
      })
      .catch((cause: unknown) => { if (active) setError(cause instanceof Error ? cause.message : 'Unable to load scan details.'); })
      .finally(() => { if (active) setLoadedScanId(requestedScanId); });
    return () => { active = false; };
  }, [requestedScanId]);

  useEffect(() => {
    if (!scanStatus || !activeStatuses.has(scanStatus)) return;
    const interval = window.setInterval(() => {
      refresh().catch((cause: unknown) => setError(cause instanceof Error ? cause.message : 'Unable to refresh scan status.'));
    }, 3000);
    return () => window.clearInterval(interval);
  }, [scanStatus, refresh]);

  const handleCancel = async () => {
    if (!scan) return;
    setIsCancelling(true);
    setError('');
    try {
      setScan(await apiClient.cancelScan(scan.scanId));
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to cancel scan.');
    } finally {
      setIsCancelling(false);
    }
  };

  if (loadedScanId !== requestedScanId) return <div className="page-loading">Loading scan details…</div>;
  if (!scan || scan.scanId !== requestedScanId) {
    return (
      <EmptyState
        title="Scan not found"
        description={error || 'No scan record was returned by the backend.'}
        action={<Link to="/scans/history" className="primary-button"><ArrowLeft size={14} />Return to history</Link>}
      />
    );
  }

  return (
    <div className="content-stack">
      <div className="detail-header">
        <div>
          <div className="eyebrow">Assessment details</div>
          <h2>{scan.scanId}</h2>
        </div>
        <div className="button-row">
          {['Completed', 'Failed', 'Cancelled'].includes(scan.status) ? (
            <Link to={`/reports/${scan.scanId}`} className="secondary-button">Open assessment report</Link>
          ) : null}
          <button type="button" className="secondary-button" onClick={handleCancel} disabled={!activeStatuses.has(scan.status) || isCancelling}>
            {isCancelling ? 'Cancelling…' : 'Cancel scan'}
          </button>
          <Link to="/scans/history" className="secondary-button"><ArrowLeft size={14} />Back to scan history</Link>
        </div>
      </div>

      {error ? <div className="inline-message inline-message--error" role="alert">{error}</div> : null}
      {scan.failureReason ? <div className="inline-message inline-message--error">{scan.failureReason}</div> : null}

      <section className="section-card">
        <div className="detail-summary-grid">
          <div><p className="muted-label">Scan ID</p><h3 className="mono-text">{scan.scanId}</h3></div>
          <div><p className="muted-label">Target</p><div className="inline-row"><TargetIcon size={14} /><span>{scan.target}</span></div></div>
          <div><p className="muted-label">Status</p><StatusBadge status={scan.status} /></div>
          <div><p className="muted-label">Cases executed / generated / requested</p><span>{scan.testsCompleted}/{scan.testsTotal}/{scan.requestedCases ?? scan.testsTotal}</span></div>
          <div><p className="muted-label">Findings</p><span>{scan.findingsCount}</span></div>
          <div><p className="muted-label">Execution time</p><div className="inline-row"><Clock3 size={14} /><span>{scan.duration}</span></div></div>
        </div>
        {scan.coverageWarning ? <div className="inline-message inline-message--warning" role="status">{scan.coverageWarning}</div> : null}
        <div className="detail-list">
          <div><span>Requested categories</span><strong>{scan.requestedCategories?.join(', ') || 'Not recorded'}</strong></div>
          <div><span>Generated categories</span><strong>{scan.generatedCategories?.join(', ') || 'None generated'}</strong></div>
          <div><span>Executed categories</span><strong>{scan.executedCategories?.join(', ') || 'None executed'}</strong></div>
          <div><span>Category coverage</span><strong>{scan.categoryCoveragePercent ?? 0}%</strong></div>
        </div>
      </section>

      <section className="section-card">
        <div className="section-card__header">
          <div><h2>Generated test cases and execution results</h2><p>Only cases and outcomes returned by the backend are shown.</p></div>
        </div>
        {!results.length ? (
          <p className="empty-copy">{activeStatuses.has(scan.status) ? 'Results will appear as cases finish executing.' : 'The backend returned no execution results for this scan.'}</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Case</th><th>Category</th><th>Provider / model</th><th>Execution</th><th>Duration</th><th>Tokens</th><th>Analysis outcome</th><th>Result</th></tr></thead>
              <tbody>
                {results.map((result) => (
                  <tr key={result.case.case_id}>
                    <td>
                      <strong className="mono-text">{result.case.case_id}</strong>
                      <p className="scan-case-prompt">{result.case.prompt}</p>
                    </td>
                    <td>{result.case.category}</td>
                    <td>{result.execution.provider ?? '—'}{result.execution.model ? ` / ${result.execution.model}` : ''}</td>
                    <td>{result.execution.status}{result.execution.status_code ? ` (${result.execution.status_code})` : ''}</td>
                    <td>{result.execution.response_time_ms == null ? '—' : `${result.execution.response_time_ms.toFixed(1)} ms`}</td>
                    <td>{result.execution.total_tokens ?? '—'}</td>
                    <td>{(result.analysis.outcome ?? result.analysis.status).replace(/_/g, ' ')}</td>
                    <td>
                      <div>{result.execution.response_body || result.execution.message || 'No response body returned.'}</div>
                      {result.execution.failure_reason ? <small>Failure reason: {result.execution.failure_reason}</small> : null}
                      {result.execution.response_truncated ? <small>Response truncated by backend.</small> : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="section-card">
        <div className="section-card__header">
          <div><h2>Findings linked to this scan</h2><p>Analyzer findings and their originating test cases.</p></div>
        </div>
        {!findings.length ? <p className="empty-copy">No findings have been returned for this scan.</p> : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Finding</th><th>Category</th><th>Severity</th><th>Confidence</th><th>Test case</th></tr></thead>
              <tbody>
                {findings.map((finding) => (
                  <tr key={finding.findingId}>
                    <td><Link to={`/findings/${finding.findingId}`} className="inline-link">{finding.vulnerabilityType}</Link></td>
                    <td>{finding.category?.replace(/_/g, ' ')}</td>
                    <td>{finding.severity}</td>
                    <td>{finding.confidence}</td>
                    <td className="mono-text">{finding.testId}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="section-card">
        <div className="section-card__header"><div><h2>Scan execution summary</h2><p>Backend-reported status and times.</p></div></div>
        <div className="detail-list">
          <div><span>Started</span><strong>{scan.startedAt ? new Date(scan.startedAt).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' }) : 'Not started'}</strong></div>
          <div><span>Completed</span><strong>{scan.endedAt ? new Date(scan.endedAt).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' }) : 'Not completed'}</strong></div>
          <div><span>Progress</span><strong>{scan.progress ?? 0}%</strong></div>
          <div><span>Execution engine</span><strong><Gauge size={14} /> Backend scheduler</strong></div>
        </div>
      </section>
    </div>
  );
}
