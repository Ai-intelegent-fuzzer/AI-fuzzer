import { Search } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { EmptyState } from '../components/common/EmptyState';
import { SectionCard } from '../components/common/SectionCard';
import { StatusBadge } from '../components/common/StatusBadge';
import { apiClient } from '../services/api';
import type { Scan } from '../types';

export function ScanHistoryPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    apiClient.getScans()
      .then(setScans)
      .catch((cause: unknown) => setError(cause instanceof Error ? cause.message : 'Unable to load scan history.'))
      .finally(() => setLoading(false));
  }, []);

  const visibleScans = useMemo(() => scans.filter((scan) =>
    `${scan.scanId} ${scan.target} ${scan.status}`.toLowerCase().includes(search.toLowerCase())), [scans, search]);

  return (
    <div className="content-stack">
      <SectionCard title="Scan History" subtitle="Execution timeline and prior assessments">
        {error ? <div className="inline-message inline-message--error" role="alert">{error}</div> : null}
        <div className="toolbar-row">
          <div className="search-box" aria-label="Search scan history">
            <Search size={15} />
            <input type="text" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search scans" aria-label="Search scans" />
          </div>
        </div>

        {loading ? <div className="page-loading">Loading scans…</div> : null}
        {!loading && !error && visibleScans.length === 0 ? (
          <EmptyState title={search ? 'No matching scans' : 'No scans yet'} description={search ? 'Try another scan ID, target, or status.' : 'Start an authorized scan to see live execution history here.'} />
        ) : null}

        {!loading && visibleScans.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Scan ID</th><th>Target</th><th>Status</th><th>Tests</th><th>Findings</th><th>Started</th><th>Duration</th></tr>
              </thead>
              <tbody>
                {visibleScans.map((scan) => (
                  <tr key={scan.scanId}>
                    <td className="mono-text"><Link to={`/scans/${scan.scanId}`} className="inline-link">{scan.scanId}</Link></td>
                    <td>{scan.target}</td>
                    <td><StatusBadge status={scan.status} /></td>
                    <td>{scan.testsCompleted}/{scan.testsTotal}</td>
                    <td>{scan.findingsCount}</td>
                    <td>{new Date(scan.startedAt).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' })}</td>
                    <td>{scan.duration}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </SectionCard>
    </div>
  );
}
