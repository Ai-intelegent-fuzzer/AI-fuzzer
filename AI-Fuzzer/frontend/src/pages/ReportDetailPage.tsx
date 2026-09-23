import { useEffect, useState } from 'react';
import { ArrowLeft, FileJson, Printer, ShieldAlert } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { EmptyState } from '../components/common/EmptyState';
import { mockAppService } from '../services/mockApi';
import type { Report } from '../types';

export function ReportDetailPage() {
  const { reportId } = useParams();
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;

    mockAppService
      .getReport(reportId ?? '')
      .then((result) => {
        if (isMounted) {
          setReport(result);
        }
      })
      .finally(() => {
        if (isMounted) {
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [reportId]);

  if (loading) {
    return <div className="page-loading">Loading report summary…</div>;
  }

  if (!report) {
    return (
      <EmptyState
        title="Report not found"
        description="The selected assessment report is not available in the mock dataset."
        action={
          <Link to="/reports" className="primary-button">
            <ArrowLeft size={14} />
            Back to reports
          </Link>
        }
      />
    );
  }

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${report.reportId.toLowerCase()}-report.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="content-stack">
      <div className="detail-header">
        <div>
          <div className="eyebrow">Report summary</div>
          <h2>{report.title}</h2>
        </div>
        <div className="action-stack action-stack--inline">
          <button type="button" className="secondary-button" onClick={() => window.print()}>
            <Printer size={14} />
            Print / Save PDF
          </button>
          <button type="button" className="primary-button" onClick={handleExportJson}>
            <FileJson size={14} />
            Export JSON
          </button>
        </div>
      </div>

      <section className="section-card">
        <div className="detail-summary-grid">
          <div>
            <p className="muted-label">Report ID</p>
            <strong>{report.reportId}</strong>
          </div>
          <div>
            <p className="muted-label">Target</p>
            <strong>{report.targetName ?? 'Customer Support AI'}</strong>
          </div>
          <div>
            <p className="muted-label">Generated</p>
            <span>{new Date(report.generatedAt).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' })}</span>
          </div>
          <div>
            <p className="muted-label">Highest severity</p>
            <span>{report.highestSeverity ?? 'High'}</span>
          </div>
        </div>
      </section>

      <div className="two-column-grid">
        <section className="section-card">
          <div className="section-card__header">
            <div>
              <h2>Executive summary</h2>
              <p>Key project-level findings.</p>
            </div>
          </div>
          <p className="report-text">{report.executiveSummary ?? report.summary}</p>
        </section>

        <section className="section-card">
          <div className="section-card__header">
            <div>
              <h2>Target information</h2>
              <p>Platform and evidence context.</p>
            </div>
          </div>
          <p className="report-text">{report.targetInformation ?? 'Target information is available in the mock environment and intentionally excludes production identifiers.'}</p>
        </section>
      </div>

      <div className="two-column-grid">
        <section className="section-card">
          <div className="section-card__header">
            <div>
              <h2>Scan configuration</h2>
              <p>Configuration used for the executed scan.</p>
            </div>
          </div>
          <p className="report-text">{report.scanConfiguration ?? 'Standard prompt validation, safe demo mode, and evidence retention enabled.'}</p>
        </section>

        <section className="section-card">
          <div className="section-card__header">
            <div>
              <h2>Findings summary</h2>
              <p>Operational results by severity.</p>
            </div>
          </div>
          <div className="detail-list">
            <div><span>Tests executed</span><strong>{report.testsExecuted ?? 420}</strong></div>
            <div><span>Findings</span><strong>{report.findingsCount}</strong></div>
            <div><span>Status</span><strong>{report.status}</strong></div>
          </div>
        </section>
      </div>

      <section className="section-card">
        <div className="section-card__header">
          <div>
            <h2>Severity distribution</h2>
            <p>Distribution across the executed report.</p>
          </div>
        </div>
        <div className="distribution-list">
          {(report.severityDistribution ?? [{ name: 'High', value: 2 }, { name: 'Medium', value: 3 }, { name: 'Low', value: 4 }]).map((item) => (
            <div key={item.name} className="distribution-item">
              <span>{item.name}</span>
              <strong>{item.value}</strong>
            </div>
          ))}
        </div>
      </section>

      <div className="two-column-grid">
        <section className="section-card">
          <div className="section-card__header">
            <div>
              <h2>Detailed findings</h2>
              <p>Evidence-backed issue summaries.</p>
            </div>
          </div>
          <div className="report-findings-list">
            {(report.detailedFindings ?? []).map((finding) => (
              <div key={finding.id} className="report-finding-card">
                <div className="report-finding-card__topline">
                  <span className="mono-text">{finding.id}</span>
                  <span className={`severity-badge severity-badge--${finding.severity.toLowerCase()}`}>{finding.severity}</span>
                </div>
                <h3>{finding.type}</h3>
                <p>{finding.description}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="section-card">
          <div className="section-card__header">
            <div>
              <h2>Evidence references</h2>
              <p>Artifacts and recommendation sources.</p>
            </div>
          </div>
          <div className="detail-list">
            {(report.evidenceReferences ?? ['Synthetic evidence package generated for internal review.']).map((reference) => (
              <div key={reference}><span>Reference</span><strong>{reference}</strong></div>
            ))}
          </div>
          <div className="detail-block detail-block--stacked detail-block--alert">
            <div className="detail-block__icon"><ShieldAlert size={16} /></div>
            <p>{report.recommendedRemediation?.join(' ') ?? 'Ensure the model enforces policy boundaries, validates untrusted inputs, and logs synthetic evidence before release.'}</p>
          </div>
        </section>
      </div>
    </div>
  );
}
