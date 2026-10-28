import { useState } from 'react';
import { FileJson, Search } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { EmptyState } from '../components/common/EmptyState';
import { SectionCard } from '../components/common/SectionCard';

export function ReportsPage() {
  const [scanId, setScanId] = useState('');
  const navigate = useNavigate();

  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const value = scanId.trim();
    if (value) navigate(`/reports/${encodeURIComponent(value)}`);
  };

  return (
    <div className="content-stack">
      <SectionCard title="Assessment Reports" subtitle="Generate a report from a real scan record and its results">
        <form className="toolbar-row" onSubmit={handleSubmit}>
          <div className="search-box">
            <Search size={15} />
            <input
              type="text"
              value={scanId}
              onChange={(event) => setScanId(event.target.value)}
              placeholder="Enter scan ID"
              aria-label="Scan ID for report"
              required
            />
          </div>
          <button type="submit" className="primary-button"><FileJson size={14} /> Open report</button>
        </form>
        <EmptyState
          title="Reports are generated on demand"
          description="The backend does not provide a report-list or report-generation API. The frontend can assemble a JSON export from scan data that the backend actually returns."
        />
      </SectionCard>
    </div>
  );
}
