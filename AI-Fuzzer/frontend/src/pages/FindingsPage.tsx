import { AlertTriangle, Search } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ConfidenceBadge } from '../components/common/ConfidenceBadge';
import { EmptyState } from '../components/common/EmptyState';
import { SectionCard } from '../components/common/SectionCard';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { apiClient } from '../services/api';
import type { Finding } from '../types';

export function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [loadedFilterKey, setLoadedFilterKey] = useState('');
  const [error, setError] = useState('');
  const filterKey = `${categoryFilter}|${severityFilter}|${statusFilter}`;

  useEffect(() => {
    let active = true;
    apiClient.getFindings({
      category: categoryFilter || undefined,
      severity: severityFilter || undefined,
      status: statusFilter || undefined,
    })
      .then((items) => {
        if (active) {
          setFindings(items);
          setError('');
        }
      })
      .catch((cause: unknown) => { if (active) setError(cause instanceof Error ? cause.message : 'Unable to load findings.'); })
      .finally(() => { if (active) setLoadedFilterKey(filterKey); });
    return () => { active = false; };
  }, [categoryFilter, severityFilter, statusFilter, filterKey]);
  const loading = loadedFilterKey !== filterKey;

  const filteredFindings = useMemo(() => findings.filter((finding) =>
    `${finding.vulnerabilityType} ${finding.targetName} ${finding.findingId} ${finding.testId}`
      .toLowerCase().includes(search.toLowerCase())), [findings, search]);
  const categoryOptions = Array.from(new Set(findings.flatMap((item) => item.category ? [item.category] : []))).sort();
  const latestFinding = filteredFindings[0];

  return (
    <div className="content-stack">
      <SectionCard title="Vulnerability Findings" subtitle="Observed issues with evidence and recommended remediation">
        {error ? <div className="inline-message inline-message--error" role="alert">{error}</div> : null}
        <div className="toolbar-row toolbar-row--filters">
          <div className="search-box" aria-label="Search findings">
            <Search size={15} />
            <input type="text" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Filter findings" aria-label="Filter findings" />
          </div>
          <select value={categoryFilter} onChange={(event) => setCategoryFilter(event.target.value)} className="compact-select" aria-label="Filter by category">
            <option value="">All categories</option>
            {categoryOptions.map((category) => <option key={category} value={category}>{category.replace(/_/g, ' ')}</option>)}
          </select>
          <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)} className="compact-select" aria-label="Filter by severity">
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="informational">Informational</option>
          </select>
          <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)} className="compact-select" aria-label="Filter by analysis status">
            <option value="">All analysis statuses</option>
            <option value="fail">Fail</option>
            <option value="pass">Pass</option>
            <option value="inconclusive">Inconclusive</option>
          </select>
        </div>

        {loading ? <div className="page-loading">Loading findings…</div> : null}
        {!loading && !error && !filteredFindings.length ? (
          <EmptyState title={search || categoryFilter || severityFilter || statusFilter ? 'No matching findings' : 'No findings yet'} description={search || categoryFilter || severityFilter || statusFilter ? 'Adjust the filters to see other results.' : 'Findings from completed or partially executed scans will appear here.'} />
        ) : null}
        {!loading && filteredFindings.length > 0 ? (
          <div className="findings-table-wrap">
            <table>
              <thead>
                <tr><th>Finding ID</th><th>Vulnerability</th><th>Severity</th><th>Confidence</th><th>Target</th><th>Test ID</th><th>Timestamp</th></tr>
              </thead>
              <tbody>
                {filteredFindings.map((finding) => (
                  <tr key={finding.findingId}>
                    <td className="mono-text"><Link to={`/findings/${finding.findingId}`} className="inline-link">{finding.findingId}</Link></td>
                    <td>{finding.vulnerabilityType}</td>
                    <td><SeverityBadge severity={finding.severity} /></td>
                    <td><ConfidenceBadge confidence={finding.confidence} /></td>
                    <td>{finding.targetName}</td>
                    <td className="mono-text">{finding.testId}</td>
                    <td>{new Date(finding.timestamp).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' })}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </SectionCard>

      {latestFinding ? (
        <SectionCard title="Latest evidence" subtitle="Evidence and remediation from a real analyzer finding">
          <div className="evidence-panel">
            <div className="evidence-panel__header">
              <div className="evidence-pill"><AlertTriangle size={14} />{latestFinding.severity}</div>
              <span className="mono-text">{latestFinding.findingId}</span>
            </div>
            <h3>{latestFinding.vulnerabilityType}</h3>
            <p>{latestFinding.evidence}</p>
            <div className="evidence-grid">
              <div><label>Expected behavior</label><p>{latestFinding.expectedBehavior}</p></div>
              <div><label>Actual behavior</label><p>{latestFinding.actualBehavior}</p></div>
              <div><label>Confidence / analysis</label><p>{latestFinding.confidence} / {latestFinding.analysisStatus ?? 'not recorded'}</p></div>
              <div><label>Recommendation</label><p>{latestFinding.recommendation}</p></div>
            </div>
          </div>
        </SectionCard>
      ) : null}
    </div>
  );
}
