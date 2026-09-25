import { Download, FileJson, FileText } from 'lucide-react';
import { Link } from 'react-router-dom';
import { SectionCard } from '../components/common/SectionCard';
import { mockReports } from '../data/mockData';

export function ReportsPage() {
  const handleDownloadJson = (reportId: string, title: string) => {
    const report = mockReports.find((item) => item.reportId === reportId);
    if (!report) {
      return;
    }

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-report.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="content-stack">
      <SectionCard title="Assessment Reports" subtitle="JSON and PDF exports for executive and technical review">
        <div className="report-grid">
          {mockReports.map((report) => (
            <article key={report.reportId} className="report-card">
              <div className="report-card__icon">
                {report.format === 'JSON' ? <FileJson size={18} /> : <FileText size={18} />}
              </div>

              <div className="report-card__body">
                <div className="report-card__header">
                  <h3>{report.title}</h3>
                  <span className="report-format">{report.format}</span>
                </div>
                <p>{report.summary}</p>
                <div className="report-card__meta">
                  <span>{report.reportId}</span>
                  <span>{report.findingsCount} findings</span>
                  <span>{new Date(report.generatedAt).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}</span>
                </div>
              </div>

              <div className="button-row button-row--stacked">
                <Link to={`/reports/${report.reportId}`} className="secondary-button" state={{ fromReports: true }}>
                  Open report
                </Link>
                <button type="button" className="secondary-button" onClick={() => handleDownloadJson(report.reportId, report.title)}>
                  <Download size={14} />
                  Download JSON
                </button>
              </div>
            </article>
          ))}
        </div>
      </SectionCard>
    </div>
  );
}
