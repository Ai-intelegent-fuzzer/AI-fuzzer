import { useEffect, useState } from 'react';
import {
  AlertTriangle,
  Gauge,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { MetricCard } from '../components/common/MetricCard';
import { SectionCard } from '../components/common/SectionCard';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { ConfidenceBadge } from '../components/common/ConfidenceBadge';
import { mockAppService } from '../services/mockApi';
import {
  severityDistribution,
  vulnerabilityDistribution,
} from '../data/mockData';
import type { DashboardSummary, Finding, Scan, SystemHealthState } from '../types';

const pieColors = ['#5bc0ff', '#7dd3fc', '#fbbf24', '#f97316'];

export function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [health, setHealth] = useState<SystemHealthState | null>(null);

  useEffect(() => {
    Promise.all([
      mockAppService.getDashboardSummary(),
      mockAppService.getScans(),
      mockAppService.getFindings(),
      mockAppService.getSystemHealth(),
    ]).then(([metrics, scanData, findingData, healthData]) => {
      setSummary(metrics);
      setScans(scanData);
      setFindings(findingData);
      setHealth(healthData);
    });
  }, []);

  if (!summary || !health) {
    return <div className="page-loading">Loading dashboard…</div>;
  }

  return (
    <div className="dashboard-page">
      <div className="dashboard-hero">
        <div>
          <p className="eyebrow">Security overview</p>
          <h2>Monitor AI security scans, vulnerabilities, and testing activity.</h2>
        </div>
        <Link to="/scans/new" className="primary-button">
          <Sparkles size={16} />
          New Security Scan
        </Link>
      </div>

      <div className="metric-grid">
        <MetricCard
          icon={<ShieldCheck size={18} />}
          label="Total Scans"
          value={String(summary.totalScans)}
          detail="Across 4 active targets"
          tone="default"
        />
        <MetricCard
          icon={<Gauge size={18} />}
          label="Tests Executed"
          value={String(summary.testsExecuted)}
          detail="Across all scan stages"
          tone="success"
        />
        <MetricCard
          icon={<AlertTriangle size={18} />}
          label="Vulnerabilities Found"
          value={String(summary.vulnerabilitiesFound)}
          detail="High confidence findings"
          tone="warning"
        />
        <MetricCard
          icon={<ShieldAlert size={18} />}
          label="Critical / High"
          value={String(summary.criticalHighFindings)}
          detail="Require immediate review"
          tone="danger"
        />
      </div>

      <div className="health-grid">
        <div className="health-panel">
          <div className="health-panel__label">Scanner Engine</div>
          <div className="health-panel__value">{health.scannerEngine}</div>
        </div>
        <div className="health-panel">
          <div className="health-panel__label">Response Analyzer</div>
          <div className="health-panel__value">{health.responseAnalyzer}</div>
        </div>
        <div className="health-panel">
          <div className="health-panel__label">Evidence Store</div>
          <div className="health-panel__value">{health.evidenceStore}</div>
        </div>
        <div className="health-panel">
          <div className="health-panel__label">Active Scans</div>
          <div className="health-panel__value">{health.activeScans}</div>
        </div>
      </div>

      <div className="chart-grid">
        <SectionCard title="Severity Distribution" subtitle="Detected risk mix across completed scans">
          <div className="chart-wrap chart-wrap--bar">
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={severityDistribution} margin={{ top: 12, right: 8, left: -18, bottom: 6 }}>
                <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fill: '#a8b3c7', fontSize: 12 }} />
                <YAxis axisLine={false} tickLine={false} tick={{ fill: '#a8b3c7', fontSize: 12 }} />
                <Tooltip
                  contentStyle={{
                    background: '#141b2d',
                    border: '1px solid #21314a',
                    borderRadius: '10px',
                    color: '#f0f7ff',
                  }}
                />
                <Bar dataKey="value" radius={[8, 8, 0, 0]}>
                  {severityDistribution.map((entry, index) => (
                    <Cell
                      key={entry.name}
                      fill={['#ef4444', '#f97316', '#fbbf24', '#60a5fa', '#7dd3fc'][index]}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </SectionCard>

        <SectionCard title="Vulnerability Distribution" subtitle="Core AI security categories in current test set">
          <div className="chart-wrap chart-wrap--pie">
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={vulnerabilityDistribution}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={52}
                  outerRadius={80}
                  paddingAngle={4}
                >
                  {vulnerabilityDistribution.map((entry, index) => (
                    <Cell key={entry.name} fill={pieColors[index % pieColors.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: '#141b2d',
                    border: '1px solid #21314a',
                    borderRadius: '10px',
                    color: '#f0f7ff',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="legend-list">
              {vulnerabilityDistribution.map((entry, index) => (
                <div key={entry.name} className="legend-item">
                  <span className="legend-dot" style={{ backgroundColor: pieColors[index % pieColors.length] }} />
                  <span>{entry.name}</span>
                  <strong>{entry.value}</strong>
                </div>
              ))}
            </div>
          </div>
        </SectionCard>
      </div>

      <div className="two-column-grid">
        <SectionCard title="Recent Scans" subtitle="Latest execution activity" className="table-card">
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
                {scans.map((scan) => (
                  <tr key={scan.scanId}>
                    <td className="mono-text">
                      <Link to={`/scans/${scan.scanId}`} className="inline-link">{scan.scanId}</Link>
                    </td>
                    <td>{scan.target}</td>
                    <td><StatusBadge status={scan.status} /></td>
                    <td>{scan.testsCompleted}/{scan.testsTotal}</td>
                    <td>{scan.findingsCount}</td>
                    <td>{new Date(scan.startedAt).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}</td>
                    <td>{scan.duration}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </SectionCard>

        <SectionCard title="Recent Findings" subtitle="Most recent vulnerability detections" className="findings-card">
          <div className="finding-list">
            {findings.slice(0, 4).map((finding) => (
              <Link key={finding.findingId} to={`/findings/${finding.findingId}`} className="finding-item finding-item--link">
                <div className="finding-item__meta">
                  <span className="mono-text">{finding.findingId}</span>
                  <SeverityBadge severity={finding.severity} />
                </div>
                <div className="finding-item__summary">
                  <div>
                    <strong>{finding.vulnerabilityType}</strong>
                    <small>{finding.targetName}</small>
                  </div>
                  <ConfidenceBadge confidence={finding.confidence} />
                </div>
                <div className="finding-item__time">{new Date(finding.timestamp).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' })}</div>
              </Link>
            ))}
          </div>
        </SectionCard>
      </div>
    </div>
  );
}
