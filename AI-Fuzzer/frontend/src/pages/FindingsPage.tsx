import { AlertTriangle, Search } from 'lucide-react';
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ConfidenceBadge } from '../components/common/ConfidenceBadge';
import { SectionCard } from '../components/common/SectionCard';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { mockFindings } from '../data/mockData';

export function FindingsPage() {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [confidenceFilter, setConfidenceFilter] = useState('All');
  const [targetFilter, setTargetFilter] = useState('All');

  const filteredFindings = useMemo(() => {
    return mockFindings.filter((finding) => {
      const matchesSearch = `${finding.vulnerabilityType} ${finding.targetName} ${finding.findingId}`
        .toLowerCase()
        .includes(search.toLowerCase());
      const matchesSeverity = severityFilter === 'All' || finding.severity === severityFilter;
      const matchesConfidence = confidenceFilter === 'All' || finding.confidence === confidenceFilter;
      const matchesTarget = targetFilter === 'All' || finding.targetName === targetFilter;
      return matchesSearch && matchesSeverity && matchesConfidence && matchesTarget;
    });
  }, [search, severityFilter, confidenceFilter, targetFilter]);

  const targetOptions = Array.from(new Set(mockFindings.map((item) => item.targetName)));
  const latestFinding = filteredFindings[0] ?? mockFindings[0];

  return (
    <div className="content-stack">
      <SectionCard title="Vulnerability Findings" subtitle="Observed issues with evidence and recommended remediation">
        <div className="toolbar-row toolbar-row--filters">
          <div className="search-box" aria-label="Search findings">
            <Search size={15} />
            <input type="text" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Filter findings" aria-label="Filter findings" />
          </div>
          <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)} className="compact-select" aria-label="Filter by severity">
            <option value="All">All severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
          <select value={confidenceFilter} onChange={(event) => setConfidenceFilter(event.target.value)} className="compact-select" aria-label="Filter by confidence">
            <option value="All">All confidence</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
          <select value={targetFilter} onChange={(event) => setTargetFilter(event.target.value)} className="compact-select" aria-label="Filter by target">
            <option value="All">All targets</option>
            {targetOptions.map((target) => (
              <option key={target} value={target}>{target}</option>
            ))}
          </select>
        </div>

        <div className="findings-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Finding ID</th>
                <th>Vulnerability</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Target</th>
                <th>Test ID</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {filteredFindings.map((finding) => (
                <tr key={finding.findingId}>
                  <td className="mono-text">
                    <Link to={`/findings/${finding.findingId}`} className="inline-link">{finding.findingId}</Link>
                  </td>
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
      </SectionCard>

      <SectionCard title="Latest evidence" subtitle="Detailed forensic review of the most recent run">
        <div className="evidence-panel">
          <div className="evidence-panel__header">
            <div className="evidence-pill">
              <AlertTriangle size={14} />
              {latestFinding.severity}
            </div>
            <span className="mono-text">{latestFinding.findingId}</span>
          </div>
          <h3>{latestFinding.vulnerabilityType}</h3>
          <p>
            {latestFinding.evidence}
          </p>
          <div className="evidence-grid">
            <div>
              <label>Expected behavior</label>
              <p>{latestFinding.expectedBehavior}</p>
            </div>
            <div>
              <label>Actual behavior</label>
              <p>{latestFinding.actualBehavior}</p>
            </div>
            <div>
              <label>Evidence</label>
              <p>{latestFinding.evidence}</p>
            </div>
            <div>
              <label>Recommendation</label>
              <p>{latestFinding.recommendation}</p>
            </div>
          </div>
        </div>
      </SectionCard>
    </div>
  );
}
