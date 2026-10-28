import { useState } from 'react';
import { Search } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { EmptyState } from '../components/common/EmptyState';
import { SectionCard } from '../components/common/SectionCard';

export function ScanHistoryPage() {
  const [scanId, setScanId] = useState('');
  const navigate = useNavigate();

  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const value = scanId.trim();
    if (value) {
      navigate(`/scans/${encodeURIComponent(value)}`);
    }
  };

  return (
    <div className="content-stack">
      <SectionCard title="Scan History" subtitle="Look up an existing scan record by its backend ID">
        <form className="toolbar-row" onSubmit={handleSubmit}>
          <div className="search-box">
            <Search size={15} />
            <input
              type="text"
              value={scanId}
              onChange={(event) => setScanId(event.target.value)}
              placeholder="Enter scan ID"
              aria-label="Scan ID"
              required
            />
          </div>
          <button type="submit" className="primary-button">Load scan</button>
        </form>
        <EmptyState
          title="The backend does not provide a scan-list endpoint"
          description="Scan records are held in memory and can only be retrieved when their exact ID is known. IDs are lost when the backend restarts."
        />
      </SectionCard>
    </div>
  );
}
