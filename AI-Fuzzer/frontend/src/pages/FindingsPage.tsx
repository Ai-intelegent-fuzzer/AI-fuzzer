import { useMemo, useState } from 'react';
import { AlertTriangle, Search } from 'lucide-react';
import { Link } from 'react-router-dom';
import { ConfidenceBadge } from '../components/common/ConfidenceBadge';
import { EmptyState } from '../components/common/EmptyState';
import { SectionCard } from '../components/common/SectionCard';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { ApiError, getScanResults } from '../services/api';
import type { ApiFinding, ApiScanResult } from '../types';

interface FindingRow {
  finding: ApiFinding;
  scanId: string;
  targetId: string;
  verdict: string;
}

export function FindingsPage() {
  const [scanId, setScanId] = useState('');
  const [loadedScanId, setLoadedScanId] = useState('');
  const [results, setResults] = useState<ApiScanResult[]>([]);
  const [search, setSearch] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const loadFindings = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const value = scanId.trim();
    if (!value) return;
    setLoading(true);
    setError('');
    setResults([]);
    setLoadedScanId('');
    try {
      setResults(await getScanResults(value));
      setLoadedScanId(value);
    } catch (requestError) {
      setError(requestError instanceof ApiError ? requestError.message : 'Unable to load scan findings.');
    } finally {
      setLoading(false);
    }
  };

  const rows = useMemo<FindingRow[]>(() => results.flatMap((result) =>
    result.analysis.findings.map((finding) => ({
      finding,
      scanId: loadedScanId,
      targetId: result.analysis.target_id,
      verdict: result.analysis.status,
    })),
  ).filter(({ finding }) =>
    `${finding.title} ${finding.category} ${finding.finding_id}`
      .toLowerCase()
      .includes(search.toLowerCase()),
  ), [loadedScanId, results, search]);

  return (
    <div className="content-stack">
      <SectionCard title="Findings" subtitle="Analyzer findings from actual scan-result records">
        <form className="toolbar-row" onSubmit={loadFindings}>
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
          <button type="submit" className="primary-button" disabled={loading}>
            {loading ? 'Loading…' : 'Load findings'}
          </button>
          {loadedScanId ? (
            <input
              type="search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Filter loaded findings"
              aria-label="Filter findings"
            />
          ) : null}
        </form>

        {error ? <div className="inline-message inline-message--error" role="alert">{error}</div> : null}
        {loading ? <div className="page-loading">Loading scan results…</div> : null}

        {!loading && loadedScanId && rows.length === 0 ? (
          <EmptyState
            title="No analyzer findings returned"
            description="This scan returned no finding records, or no records match the filter. Execution errors are not counted as vulnerabilities."
          />
        ) : null}

        {!loading && rows.length > 0 ? (
          <div className="findings-table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Finding ID</th>
                  <th>Finding</th>
                  <th>Severity</th>
                  <th>Confidence</th>
                  <th>Category</th>
                  <th>Verdict</th>
                  <th>Test ID</th>
                </tr>
              </thead>
              <tbody>
                {rows.map(({ finding, scanId: id, targetId, verdict }) => (
                  <tr key={finding.finding_id}>
                    <td className="mono-text">
                      <Link
                        to={`/findings/${encodeURIComponent(finding.finding_id)}?scanId=${encodeURIComponent(id)}`}
                        className="inline-link"
                        state={{ targetId, verdict }}
                      >
                        {finding.finding_id}
                      </Link>
                    </td>
                    <td>{finding.title}</td>
                    <td><SeverityBadge severity={finding.severity} /></td>
                    <td><ConfidenceBadge confidence={finding.confidence} /></td>
                    <td>{finding.category}</td>
                    <td><span className="mono-text">{verdict.toUpperCase()}</span></td>
                    <td className="mono-text">{finding.case_id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </SectionCard>

      {loadedScanId && results.some((result) => result.execution.status.toLowerCase() !== 'success') ? (
        <SectionCard title="Execution status" subtitle="Provider/execution errors are not vulnerability findings">
          <div className="detail-block">
            <div className="detail-block__icon"><AlertTriangle size={16} /></div>
            <p>
              At least one result has a non-success execution status. Review the scan record for
              execution messages; these failures are kept separate from analyzer findings.
            </p>
          </div>
        </SectionCard>
      ) : null}
    </div>
  );
}
