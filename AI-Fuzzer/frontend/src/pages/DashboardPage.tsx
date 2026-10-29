import { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  Gauge,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { EmptyState } from '../components/common/EmptyState';
import { MetricCard } from '../components/common/MetricCard';
import { SectionCard } from '../components/common/SectionCard';
import { ApiError, getHealth, getTargets } from '../services/api';
import type { ApiHealth, ApiTarget } from '../types';

export function DashboardPage() {
  const [health, setHealth] = useState<ApiHealth | null>(null);
  const [targets, setTargets] = useState<ApiTarget[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadDashboard = useCallback(() => Promise.all([getHealth(), getTargets()])
    .then(([healthResult, targetResult]) => {
      setHealth(healthResult);
      setTargets(targetResult);
      setError('');
    })
    .catch((requestError: unknown) => {
      setError(requestError instanceof ApiError ? requestError.message : 'Unable to load backend data.');
    })
    .finally(() => setLoading(false)), []);

  useEffect(() => {
    void loadDashboard();
  }, [loadDashboard]);

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

      {error ? (
        <div className="inline-message inline-message--error" role="alert">
          <span>{error}</span>
          <button type="button" className="text-button" onClick={() => {
            setLoading(true);
            setError('');
            void loadDashboard();
          }} disabled={loading}>
            Retry
          </button>
        </div>
      ) : null}

      {loading ? <div className="page-loading">Loading live backend data…</div> : null}

      {!loading && !error ? (
        <>
          <div className="metric-grid">
            <MetricCard
              icon={<ShieldCheck size={18} />}
              label="Total Scans"
              value="Unavailable"
              detail="The backend has no scan-list or aggregate endpoint"
            />
            <MetricCard
              icon={<Gauge size={18} />}
              label="Tests Executed"
              value="Unavailable"
              detail="Execution totals are only returned for a known scan ID"
              tone="success"
            />
            <MetricCard
              icon={<AlertTriangle size={18} />}
              label="Vulnerabilities Found"
              value="Unavailable"
              detail="Findings can be reviewed after loading a scan"
              tone="warning"
            />
            <MetricCard
              icon={<ShieldAlert size={18} />}
              label="Critical / High"
              value="Unavailable"
              detail="No cross-scan severity totals are available"
              tone="danger"
            />
          </div>

          <div className="health-grid">
            <div className="health-panel">
              <div className="health-panel__label">Backend Service</div>
              <div className="health-panel__value">{health?.status ?? 'Unavailable'}</div>
            </div>
            <div className="health-panel">
              <div className="health-panel__label">Registered Targets</div>
              <div className="health-panel__value">{targets.length}</div>
            </div>
            <div className="health-panel">
              <div className="health-panel__label">Response Analyzer</div>
              <div className="health-panel__value">Not reported by health endpoint</div>
            </div>
            <div className="health-panel">
              <div className="health-panel__label">Active Scans</div>
              <div className="health-panel__value">Unavailable without a scan ID</div>
            </div>
          </div>

          <div className="chart-grid">
            <SectionCard title="Severity Distribution" subtitle="Detected risk mix across completed scans">
              <div className="chart-wrap chart-wrap--bar">
                <EmptyState
                  title="Severity totals unavailable"
                  description="The backend does not expose aggregate findings across scans. Load a known scan ID to review its findings."
                  action={<Link to="/findings" className="secondary-button">Review findings</Link>}
                />
              </div>
            </SectionCard>

            <SectionCard title="Vulnerability Distribution" subtitle="Core AI security categories in current test set">
              <div className="chart-wrap chart-wrap--pie">
                <EmptyState
                  title="Category totals unavailable"
                  description="The backend does not expose cross-scan category statistics. Scan-specific results require a known scan ID."
                  action={<Link to="/scans/history" className="secondary-button">Look up a scan</Link>}
                />
              </div>
            </SectionCard>
          </div>

          <div className="two-column-grid">
            <SectionCard title="Recent Scans" subtitle="Latest execution activity" className="table-card">
              <EmptyState
                title="The backend does not provide a scan list"
                description="Enter a known scan ID to view its status, execution metrics, and results."
                action={<Link to="/scans/history" className="secondary-button">Look up a scan</Link>}
              />
            </SectionCard>

            <SectionCard title="Recent Findings" subtitle="Most recent vulnerability detections" className="findings-card">
              <EmptyState
                title="Findings require a scan ID"
                description="The backend provides findings within scan results, but does not expose a global findings feed."
                action={<Link to="/findings" className="secondary-button">Review findings</Link>}
              />
            </SectionCard>
          </div>
        </>
      ) : null}
    </div>
  );
}
