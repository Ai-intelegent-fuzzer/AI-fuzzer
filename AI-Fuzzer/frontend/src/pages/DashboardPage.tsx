import { useCallback, useEffect, useState } from 'react';
import { Activity, Server, Target as TargetIcon } from 'lucide-react';
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
    <div className="content-stack">
      <div className="dashboard-hero">
        <div>
          <p className="eyebrow">Backend overview</p>
          <h2>Live service status and registered target inventory.</h2>
        </div>
        <Link to="/scans/history" className="primary-button">Look up a scan</Link>
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

      {!loading && !error && health ? (
        <>
          <div className="metric-grid">
            <MetricCard
              icon={<Activity size={18} />}
              label="Backend status"
              value={health.status}
              detail="Value returned by GET /health"
              tone={health.status.toLowerCase() === 'healthy' ? 'success' : 'warning'}
            />
            <MetricCard
              icon={<TargetIcon size={18} />}
              label="Registered targets"
              value={String(targets.length)}
              detail="Current in-memory target registry"
              tone="default"
            />
            <MetricCard
              icon={<Server size={18} />}
              label="Scan history"
              value="ID lookup"
              detail="Backend does not expose a scan-list route"
              tone="default"
            />
          </div>

          <SectionCard title="Scan activity" subtitle="No scan totals or findings are inferred from unavailable endpoints.">
            <EmptyState
              title="Scan history must be opened by ID"
              description="The backend provides scan details and results when given a scan ID, but it does not provide a list or aggregate statistics endpoint."
              action={<Link to="/scans/history" className="secondary-button">Enter scan ID</Link>}
            />
          </SectionCard>
        </>
      ) : null}
    </div>
  );
}
