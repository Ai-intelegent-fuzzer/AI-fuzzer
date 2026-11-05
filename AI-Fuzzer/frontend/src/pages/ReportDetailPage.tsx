import { useEffect, useState } from 'react';
import { ArrowLeft, Download, FileJson, Printer, ShieldAlert } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { EmptyState } from '../components/common/EmptyState';
import { apiClient } from '../services/api';
import type { Report } from '../types';

const escapeHtml = (value: string) => value
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;');

function downloadReport(report: Report, format: 'html' | 'json') {
  const content = format === 'json'
    ? JSON.stringify(report, null, 2)
    : `<!doctype html><html><head><meta charset="utf-8"><title>${escapeHtml(report.title)}</title>
      <style>body{font:15px/1.6 Arial,sans-serif;max-width:900px;margin:40px auto;color:#172033}
      h1,h2{color:#102a43}section{border-bottom:1px solid #ccd5df;padding:18px 0}
      pre{white-space:pre-wrap;background:#f2f5f8;padding:12px}.finding{page-break-inside:avoid}
      @media print{@page{size:A4;margin:18mm}h1{page-break-before:always}h1:first-child{page-break-before:avoid}}</style>
      </head><body><h1>${escapeHtml(report.projectName ?? 'AI-Fuzzer')}<br>${escapeHtml(report.title)}</h1>
      <p>Report ID: ${escapeHtml(report.reportId)} · Assessment date: ${escapeHtml(new Date(report.generatedAt).toLocaleString())}</p>
      <section><h2>Scope and authorization</h2><p>${escapeHtml(report.assessmentScope ?? report.targetInformation ?? '')}</p>
      <p>${escapeHtml(report.authorizationStatement ?? '')}</p></section>
      <section><h2>Executive summary</h2><p>${escapeHtml(report.executiveSummary ?? report.summary)}</p>
      <p>${escapeHtml(report.conclusion ?? '')}</p></section>
      <section><h2>Methodology and categories</h2><p>${escapeHtml(report.methodology ?? '')}</p>
      <p>Requested: ${escapeHtml((report.categoriesRequested ?? []).join(', ') || 'Not recorded.')}</p>
      <p>Generated: ${escapeHtml((report.categoriesGenerated ?? []).join(', ') || 'None.')}</p>
      <p>Executed: ${escapeHtml((report.categoriesExecuted ?? []).join(', ') || 'None.')}</p>
      <p>Category coverage: ${report.categoryCoveragePercent ?? 0}%</p></section>
      <section><h2>Assessment statistics</h2><p>Status: ${escapeHtml(report.scanStatus ?? 'unknown')} · Requested: ${report.requestedCases ?? 0}
      · Generated: ${report.generatedCases ?? 0} · Executed: ${report.testsExecuted ?? 0} · Failed: ${report.failedExecutions ?? 0}
      · Inconclusive analyses: ${report.inconclusiveAnalyses ?? 0} · Findings: ${report.findingsCount}</p>
      <p>${escapeHtml(report.conclusion ?? '')}</p></section>
      <section><h2>Detailed findings</h2>${(report.detailedFindings ?? []).map((finding) => `<article class="finding">
      <h3>${escapeHtml(finding.type)} — ${escapeHtml(finding.severity)} (risk ${finding.riskScore ?? 'n/a'})</h3>
      <p>${escapeHtml(finding.description)}</p><p>Category: ${escapeHtml(finding.category ?? 'unknown')}
      · Confidence: ${escapeHtml(finding.confidence ?? 'unknown')} · Provider/model: ${escapeHtml(finding.provider ?? report.targetProvider ?? 'unknown')}
      / ${escapeHtml(finding.model ?? report.targetModel ?? 'unknown')}</p>
      <pre>${escapeHtml(finding.evidence)}</pre>${finding.responseExcerpt ? `<pre>${escapeHtml(finding.responseExcerpt)}</pre>` : ''}
      <p>Expected: ${escapeHtml(finding.expectedBehavior ?? 'Not recorded')}</p>
      <p>Observed: ${escapeHtml(finding.observedBehavior ?? 'Not recorded')}</p>
      <p>Recommendation: ${escapeHtml(finding.recommendation)}</p></article>`).join('') || `<p>${escapeHtml(report.conclusion ?? 'No findings were recorded; this is not a security verdict.')}</p>`}</section>
      <section><h2>Limitations</h2><ul>${(report.limitations ?? []).map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul></section>
      </body></html>`;
  const blob = new Blob([content], { type: format === 'json' ? 'application/json' : 'text/html' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `${report.reportId.toLowerCase()}-report.${format}`;
  link.click();
  URL.revokeObjectURL(url);
}

export function ReportDetailPage() {
  const { reportId } = useParams();
  const [report, setReport] = useState<Report | null>(null);
  const [loadedReportId, setLoadedReportId] = useState('');
  const [error, setError] = useState('');
  const requestedReportId = reportId ?? '';

  useEffect(() => {
    let active = true;
    apiClient.getReport(requestedReportId)
      .then((result) => {
        if (active) {
          setReport(result);
          setError('');
        }
      })
      .catch((cause: unknown) => { if (active) setError(cause instanceof Error ? cause.message : 'Unable to load report.'); })
      .finally(() => { if (active) setLoadedReportId(requestedReportId); });
    return () => { active = false; };
  }, [requestedReportId]);

  if (loadedReportId !== requestedReportId) return <div className="page-loading">Loading report summary…</div>;
  if (!report || report.reportId !== requestedReportId) {
    return (
      <EmptyState
        title="Report not found"
        description={error || 'No report was returned for the requested scan.'}
        action={<Link to="/reports" className="primary-button"><ArrowLeft size={14} />Back to reports</Link>}
      />
    );
  }

  return (
    <div className="content-stack">
      <div className="detail-header">
        <div><div className="eyebrow">Security assessment report</div><h2>{report.title}</h2></div>
        <div className="action-stack action-stack--inline">
          <button type="button" className="secondary-button" onClick={() => window.print()}><Printer size={14} />PRINT REPORT</button>
          <button type="button" className="primary-button" onClick={() => window.print()} title="In the print dialog, select Save as PDF"><Download size={14} />DOWNLOAD PDF</button>
          <button type="button" className="secondary-button" onClick={() => downloadReport(report, 'html')}><Download size={14} />Download HTML</button>
          <button type="button" className="secondary-button" onClick={() => downloadReport(report, 'json')}><FileJson size={14} />Export JSON</button>
        </div>
      </div>

      <section className="report-cover section-card">
        <p className="eyebrow">{report.projectName ?? 'AI-Fuzzer'}</p>
        <h1>{report.title}</h1>
        <div className="detail-summary-grid">
          <div><p className="muted-label">Report ID</p><strong className="mono-text">{report.reportId}</strong></div>
          <div><p className="muted-label">Assessment date</p><strong>{new Date(report.generatedAt).toLocaleDateString()}</strong></div>
          <div><p className="muted-label">Provider / model</p><strong>{report.targetProvider ?? 'Unknown'} / {report.targetModel ?? 'Unknown'}</strong></div>
          <div><p className="muted-label">Scope</p><strong>{report.assessmentScope ?? report.targetInformation}</strong></div>
        </div>
      </section>

      <section className="section-card">
        <div className="detail-summary-grid">
          <div><p className="muted-label">Report ID</p><strong className="mono-text">{report.reportId}</strong></div>
          <div><p className="muted-label">Target</p><strong>{report.targetName}</strong></div>
          <div><p className="muted-label">Generated</p><span>{new Date(report.generatedAt).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' })}</span></div>
          <div><p className="muted-label">Highest severity</p><span>{report.highestSeverity ?? 'None recorded'}</span></div>
          {report.scanId ? <div><p className="muted-label">Source scan</p><Link to={`/scans/${report.scanId}`} className="inline-link mono-text">{report.scanId}</Link></div> : null}
        </div>
      </section>

      <section className="section-card">
        <div className="section-card__header"><div><h2>Authorization and methodology</h2></div></div>
        <p className="report-text">{report.authorizationStatement}</p>
        <p className="report-text">{report.methodology}</p>
        <p><strong>Categories requested:</strong> {report.categoriesRequested?.join(', ') || 'Not recorded.'}</p>
        <p><strong>Categories generated:</strong> {report.categoriesGenerated?.join(', ') || 'None.'}</p>
        <p><strong>Categories executed:</strong> {report.categoriesExecuted?.join(', ') || 'None.'}</p>
        <p><strong>Category coverage:</strong> {report.categoryCoveragePercent ?? 0}%</p>
        {report.coverageWarning ? <div className="inline-message inline-message--warning" role="status">{report.coverageWarning}</div> : null}
      </section>

      <div className="two-column-grid">
        <section className="section-card">
          <div className="section-card__header"><div><h2>Executive summary</h2><p>Summary derived from actual scan metrics and findings.</p></div></div>
          <p className="report-text">{report.executiveSummary ?? report.summary}</p>
        </section>
        <section className="section-card">
          <div className="section-card__header"><div><h2>Target information</h2><p>Target identifiers returned by the backend.</p></div></div>
          <p className="report-text">{report.targetInformation}</p>
        </section>
      </div>

      <div className="two-column-grid">
        <section className="section-card">
          <div className="section-card__header"><div><h2>Scan configuration</h2><p>Configuration recorded for the source scan.</p></div></div>
          <p className="report-text">{report.scanConfiguration}</p>
        </section>
        <section className="section-card">
          <div className="section-card__header"><div><h2>Findings summary</h2><p>Returned execution results and findings.</p></div></div>
          <div className="detail-list">
            <div><span>Tests executed</span><strong>{report.testsExecuted ?? 0}</strong></div>
            <div><span>Findings</span><strong>{report.findingsCount}</strong></div>
            <div><span>Requested / generated</span><strong>{report.requestedCases ?? 0} / {report.generatedCases ?? 0}</strong></div>
            <div><span>Failed executions</span><strong>{report.failedExecutions ?? 0}</strong></div>
            <div><span>Inconclusive analyses</span><strong>{report.inconclusiveAnalyses ?? 0}</strong></div>
            <div><span>Category coverage</span><strong>{report.categoryCoveragePercent ?? 0}%</strong></div>
            <div><span>Status</span><strong>{report.status}</strong></div>
          </div>
        </section>
      </div>

      <section className="section-card">
        <div className="section-card__header"><div><h2>Severity distribution</h2><p>Analyzer findings grouped by severity.</p></div></div>
        {report.severityDistribution?.length ? (
          <div className="distribution-list">
            {report.severityDistribution.map((item) => <div key={item.name} className="distribution-item"><span>{item.name}</span><strong>{item.value}</strong></div>)}
          </div>
        ) : <p className="empty-copy">No severity data was returned.</p>}
      </section>

      <div className="two-column-grid">
        <section className="section-card">
          <div className="section-card__header"><div><h2>Detailed findings</h2><p>Actual evidence-backed analyzer findings.</p></div></div>
          {report.detailedFindings?.length ? (
            <div className="report-findings-list">
              {report.detailedFindings.map((finding) => (
                <div key={finding.id} className="report-finding-card">
                  <div className="report-finding-card__topline">
                    <Link to={`/findings/${finding.id}`} className="mono-text inline-link">{finding.id}</Link>
                    <span className={`severity-badge severity-badge--${finding.severity.toLowerCase()}`}>{finding.severity}</span>
                  </div>
                  <h3>{finding.type}</h3>
                  <p>{finding.description}</p>
                  <p><strong>Category:</strong> {finding.category ?? 'Unknown'} · <strong>Confidence:</strong> {finding.confidence ?? 'Unknown'} · <strong>Risk score:</strong> {finding.riskScore ?? 'Not calculated'}/100</p>
                  <p><strong>Provider / model:</strong> {finding.provider ?? report.targetProvider ?? 'Unknown'} / {finding.model ?? report.targetModel ?? 'Unknown'}</p>
                  {finding.testCaseId ? <p><strong>Test case:</strong> <span className="mono-text">{finding.testCaseId}</span></p> : null}
                  {finding.attackId ? <p><strong>Attack ID:</strong> {finding.attackId}</p> : null}
                  <pre className="code-block">{finding.evidence}</pre>
                  {finding.responseExcerpt ? <><p><strong>Sanitized response excerpt:</strong></p><pre className="code-block">{finding.responseExcerpt}</pre></> : null}
                  <p><strong>Expected behavior:</strong> {finding.expectedBehavior ?? 'Not recorded.'}</p>
                  <p><strong>Observed behavior:</strong> {finding.observedBehavior ?? 'Not recorded.'}</p>
                  <p><strong>Impact:</strong> {finding.impact ?? 'Observed response behavior; external impact was not verified.'}</p>
                  {finding.reproductionSteps?.length ? <><strong>Reproduction steps:</strong><ol>{finding.reproductionSteps.map((step) => <li key={step}>{step}</li>)}</ol></> : null}
                  <p><strong>Recommendation:</strong> {finding.recommendation}</p>
                </div>
              ))}
            </div>
          ) : <p className="empty-copy">This scan has no findings.</p>}
        </section>

        <section className="section-card">
          <div className="section-card__header"><div><h2>Evidence references</h2><p>Finding records included in this report.</p></div></div>
          {report.evidenceReferences?.length ? (
            <div className="detail-list">
              {report.evidenceReferences.map((reference) => <div key={reference}><span>Finding</span><Link to={`/findings/${reference}`} className="inline-link mono-text">{reference}</Link></div>)}
            </div>
          ) : <p className="empty-copy">No evidence references were returned.</p>}
          {report.recommendedRemediation?.length ? (
            <div className="detail-block detail-block--stacked detail-block--alert">
              <div className="detail-block__icon"><ShieldAlert size={16} /></div>
              <ul>{report.recommendedRemediation.map((recommendation) => <li key={recommendation}>{recommendation}</li>)}</ul>
            </div>
          ) : null}
        </section>
      </div>
      <section className="section-card">
        <div className="section-card__header"><div><h2>Conclusion and limitations</h2></div></div>
        <p className="report-text">{report.conclusion}</p>
        <ul>{report.limitations?.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul>
      </section>
    </div>
  );
}
