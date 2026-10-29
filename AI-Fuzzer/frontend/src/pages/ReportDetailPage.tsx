import { useEffect, useMemo, useState } from 'react';
import { ArrowLeft, FileJson, Printer } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { EmptyState } from '../components/common/EmptyState';
import { ApiError, getScan, getScanResults, getTarget } from '../services/api';
import type { ApiScanRecord, ApiScanResult, ApiTarget } from '../types';

function endpointHost(endpoint: string): string {
  try {
    return new URL(endpoint).host;
  } catch {
    return 'Not available';
  }
}

function safeFilename(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'scan-report';
}

function readableStatus(value: string): string {
  return value.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function isTerminal(status: string): boolean {
  return ['completed', 'failed', 'cancelled'].includes(status);
}

export function ReportDetailPage() {
  const { reportId = '' } = useParams();
  const scanId = reportId;
  const [scan, setScan] = useState<ApiScanRecord | null>(null);
  const [results, setResults] = useState<ApiScanResult[]>([]);
  const [target, setTarget] = useState<ApiTarget | null>(null);
  const [targetError, setTargetError] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let active = true;

    Promise.all([getScan(scanId), getScanResults(scanId)])
      .then(async ([scanRecord, scanResults]) => {
        if (!active) return;
        setScan(scanRecord);
        setResults(scanResults);
        try {
          const targetRecord = await getTarget(scanRecord.target_id);
          if (active) setTarget(targetRecord);
        } catch (requestError) {
          if (active) {
            setTargetError(requestError instanceof ApiError
              ? requestError.message
              : 'Target metadata could not be loaded.');
          }
        }
      })
      .catch((requestError: unknown) => {
        if (active) {
          setError(requestError instanceof ApiError ? requestError.message : 'Unable to load report data.');
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => { active = false; };
  }, [refreshKey, scanId]);

  const reportData = useMemo(() => {
    if (!scan) return null;
    return {
      generated_at: new Date().toISOString(),
      completeness: {
        target_metadata_available: Boolean(target),
        scan_results_complete: isTerminal(scan.status) && results.length === scan.executed_case_count,
        notes: [
          ...(!target ? ['Target metadata was unavailable.'] : []),
          ...(!isTerminal(scan.status) ? ['The scan is not in a terminal state.'] : []),
          ...(results.length !== scan.executed_case_count
            ? [`The backend returned ${results.length} result rows for ${scan.executed_case_count} executed cases.`]
            : []),
        ],
      },
      target: target
        ? {
            target_id: target.target_id,
            name: target.name,
            target_type: target.target_type,
            provider: target.provider,
            model: target.model,
            endpoint_host: endpointHost(target.endpoint),
          }
        : { target_id: scan.target_id, incomplete: true },
      scan,
      results: results.map((result) => ({
        test_case: {
          case_id: result.case.case_id,
          category: result.case.category,
          prompt: result.case.prompt,
          mutation_strategy: result.case.mutation_strategy,
          mutation_depth: result.case.mutation_depth,
        },
        execution: {
          status: result.execution.status,
          provider: result.execution.provider,
          model: result.execution.model,
          status_code: result.execution.status_code,
          response_time_ms: result.execution.response_time_ms,
          failure_reason: result.execution.failure_reason,
          response_truncated: result.execution.response_truncated,
        },
        analysis: result.analysis,
      })),
    };
  }, [results, scan, target]);

  const handleExportJson = () => {
    if (!reportData) return;
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${safeFilename(scanId)}-report.json`;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  };

  if (loading) {
    return <div className="page-loading">Loading scan report data…</div>;
  }

  if (!scan || !reportData) {
    return (
      <EmptyState
        title="Report data unavailable"
        description={error || 'The backend did not return a scan record and result set for this ID.'}
        action={
          <div className="button-row">
            <button type="button" className="primary-button" onClick={() => {
              setLoading(true);
              setError('');
              setRefreshKey((key) => key + 1);
            }} disabled={loading}>
              Retry
            </button>
            <Link to="/reports" className="secondary-button"><ArrowLeft size={14} /> Back to reports</Link>
          </div>
        }
      />
    );
  }

  const findings = results.flatMap((result) => result.analysis.findings);

  return (
    <div className="content-stack">
      {!target || !isTerminal(scan.status) || results.length !== scan.executed_case_count ? (
        <div className="inline-message inline-message--error" role="status">
          Report is incomplete. {targetError ? `Target metadata: ${targetError} ` : ''}
          {results.length !== scan.executed_case_count
            ? `The backend returned ${results.length} result rows for ${scan.executed_case_count} executed cases.`
            : ''}
        </div>
      ) : null}
      <div className="detail-header">
        <div><div className="eyebrow">Scan report</div><h2>{scan.scan_id}</h2></div>
        <div className="action-stack action-stack--inline">
          <button type="button" className="secondary-button" onClick={() => window.print()}><Printer size={14} /> Print / Save PDF</button>
          <button type="button" className="primary-button" onClick={handleExportJson}><FileJson size={14} /> Export JSON</button>
        </div>
      </div>

      <section className="section-card">
        <div className="detail-summary-grid">
          <div><p className="muted-label">Target</p><strong>{target?.name ?? scan.target_id}</strong></div>
          <div><p className="muted-label">Provider / model</p><strong>{target ? `${target.provider} / ${target.model ?? 'Not specified'}` : 'Not available'}</strong></div>
          <div><p className="muted-label">Scan status</p><strong>{readableStatus(scan.status)}</strong></div>
          <div><p className="muted-label">Completed</p><span>{scan.completed_at ? new Date(scan.completed_at).toLocaleString() : 'Not completed'}</span></div>
          <div><p className="muted-label">Tests executed</p><strong>{scan.executed_case_count}</strong></div>
          <div><p className="muted-label">Findings</p><strong>{findings.length}</strong></div>
        </div>
      </section>

      <section className="section-card">
        <div className="section-card__header"><div><h2>Result summary</h2><p>Counts and verdicts are derived from retrieved backend records only.</p></div></div>
        <div className="detail-list">
          <div><span>Result rows</span><strong>{results.length}</strong></div>
          <div><span>Analyzer PASS</span><strong>{results.filter((result) => result.analysis.status === 'pass').length}</strong></div>
          <div><span>Analyzer FAIL</span><strong>{results.filter((result) => result.analysis.status === 'fail').length}</strong></div>
          <div><span>Analyzer INCONCLUSIVE</span><strong>{results.filter((result) => result.analysis.status === 'inconclusive').length}</strong></div>
          <div><span>Execution errors</span><strong>{scan.error_count}</strong></div>
        </div>
      </section>

      <section className="section-card">
        <div className="section-card__header"><div><h2>Findings and evidence</h2><p>Analyzer output is a heuristic assessment and requires manual validation.</p></div></div>
        {findings.length === 0 ? (
          <EmptyState title="No findings returned" description="The backend returned no analyzer finding records for this scan." />
        ) : (
          <div className="content-stack">
            {findings.map((finding) => (
              <article className="evidence-panel" key={finding.finding_id}>
                <div className="evidence-panel__header">
                  <span className="mono-text">{finding.finding_id}</span>
                  <span className={`severity-badge severity-badge--${finding.severity.toLowerCase()}`}>{readableStatus(finding.severity)}</span>
                </div>
                <h3>{finding.title}</h3>
                <p>{finding.description || 'No description returned.'}</p>
                <p><strong>Category:</strong> {finding.category} · <strong>Confidence:</strong> {readableStatus(finding.confidence)}</p>
                <pre className="code-block">{finding.evidence}</pre>
                <p><strong>Recommendation:</strong> {finding.recommendation}</p>
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
