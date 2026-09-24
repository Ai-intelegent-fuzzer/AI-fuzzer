import { Search } from 'lucide-react';
import { Link } from 'react-router-dom';
import { SectionCard } from '../components/common/SectionCard';
import { StatusBadge } from '../components/common/StatusBadge';
import { mockScans } from '../data/mockData';

export function ScanHistoryPage() {
  return (
    <div className="content-stack">
      <SectionCard title="Scan History" subtitle="Execution timeline and prior assessments">
        <div className="toolbar-row">
          <div className="search-box" aria-label="Search scan history">
            <Search size={15} />
            <input type="text" placeholder="Search scans" aria-label="Search scans" />
          </div>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Scan ID</th>
                <th>Target</th>
                <th>Status</th>
                <th>Tests</th>
                <th>Findings</th>
                <th>Started</th>
                <th>Duration</th>
              </tr>
            </thead>
            <tbody>
              {mockScans.map((scan) => (
                <tr key={scan.scanId}>
                  <td className="mono-text">
                    <Link to={`/scans/${scan.scanId}`} className="inline-link">{scan.scanId}</Link>
                  </td>
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
      </SectionCard>
    </div>
  );
}
