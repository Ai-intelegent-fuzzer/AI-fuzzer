import { useEffect, useState } from 'react';
import { Download, FileJson, FileText } from 'lucide-react';
import { Link } from 'react-router-dom';
import { EmptyState } from '../components/common/EmptyState';
import { SectionCard } from '../components/common/SectionCard';
import { apiClient } from '../services/api';
import type { Report } from '../types';

export function ReportsPage() {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [downloadingId, setDownloadingId] = useState('');

  useEffect(() => {
    apiClient.getReports()
      .then(setReports)
      .catch((cause: unknown) => setError(cause instanceof Error ? cause.message : 'Unable to load reports.'))
      .finally(() => setLoading(false));
  }, []);

  const handleDownloadJson = async (reportId: string) => {
    setDownloadingId(reportId);
    setError('');
    try {
      const report = await apiClient.getReport(reportId);
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${report.reportId.toLowerCase()}-report.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to export report.');
    } finally {
      setDownloadingId('');
    }
  };

  return (
    <div className="content-stack">
      <SectionCard title="Assessment Reports" subtitle="JSON and print-ready reports generated from available backend scan results">
        {error ? <div className="inline-message inline-message--error" role="alert">{error}</div> : null}
        {loading ? <div className="page-loading">Loading reports…</div> : null}
        {!loading && !error && !reports.length ? (
          <EmptyState title="No reports available" description="Reports become available when a scan reaches a terminal state and its results are still available to the backend." />
        ) : null}
        <div className="report-grid">
          {reports.map((report) => (
            <article key={report.reportId} className="report-card">
              <div className="report-card__icon">{report.format === 'JSON' ? <FileJson size={18} /> : <FileText size={18} />}</div>
              <div className="report-card__body">
                <div className="report-card__header"><h3>{report.title}</h3><span className="report-format">{report.format}</span></div>
                <p>{report.summary}</p>
                <div className="report-card__meta">
                  <span>{report.reportId}</span>
                  <span>{report.findingsCount} findings</span>
                  <span>{new Date(report.generatedAt).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}</span>
                </div>
              </div>
              <div className="button-row button-row--stacked">
                <Link to={`/reports/${report.reportId}`} className="secondary-button">Open report</Link>
                <button type="button" className="secondary-button" onClick={() => handleDownloadJson(report.reportId)} disabled={downloadingId === report.reportId}>
                  <Download size={14} />{downloadingId === report.reportId ? 'Preparing…' : 'Download JSON'}
                </button>
              </div>
            </article>
          ))}
        </div>
      </SectionCard>
    </div>
  );
}
