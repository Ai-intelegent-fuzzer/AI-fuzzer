import { useCallback, useEffect, useState } from 'react';
import { Target as TargetIcon } from 'lucide-react';
import { EmptyState } from '../components/common/EmptyState';
import { SectionCard } from '../components/common/SectionCard';
import { ApiError, getTargets } from '../services/api';
import type { ApiTarget } from '../types';

function endpointHost(endpoint: string): string {
  try {
    return new URL(endpoint).host;
  } catch {
    return 'Host unavailable';
  }
}

export function TargetsPage() {
  const [targets, setTargets] = useState<ApiTarget[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadTargets = useCallback(() => getTargets()
    .then((targetData) => {
      setTargets(targetData);
      setError('');
    })
    .catch((requestError: unknown) => {
      setError(requestError instanceof ApiError ? requestError.message : 'Unable to load targets.');
    })
    .finally(() => setLoading(false)), []);

  useEffect(() => {
    void loadTargets();
  }, [loadTargets]);

  return (
    <div className="content-stack">
      <SectionCard title="Registered Targets" subtitle="Read-only view of targets returned by the backend">
        {error ? (
          <div className="inline-message inline-message--error" role="alert">
            <span>{error}</span>
            <button type="button" className="text-button" onClick={() => {
              setLoading(true);
              setError('');
              void loadTargets();
            }} disabled={loading}>
              Retry
            </button>
          </div>
        ) : null}

        {loading ? <div className="page-loading">Loading registered targets…</div> : null}

        {!loading && !error && targets.length === 0 ? (
          <EmptyState
            title="No targets are registered"
            description="The backend returned an empty target list. Target creation and connectivity actions are not enabled in this read-only frontend."
          />
        ) : null}

        {!loading && !error && targets.length > 0 ? (
          <div className="target-grid">
            {targets.map((target) => (
              <article key={target.target_id} className="target-card">
                <div className="target-card__header">
                  <div className="target-card__icon"><TargetIcon size={18} /></div>
                  <div>
                    <h3>{target.name}</h3>
                    <p>{target.target_type.replaceAll('_', ' ')}</p>
                  </div>
                </div>
                <dl className="target-card__details">
                  <div>
                    <dt>Target ID</dt>
                    <dd className="mono-text">{target.target_id}</dd>
                  </div>
                  <div>
                    <dt>Provider</dt>
                    <dd>{target.provider}</dd>
                  </div>
                  <div>
                    <dt>Model</dt>
                    <dd>{target.model || 'Not specified'}</dd>
                  </div>
                  <div>
                    <dt>Endpoint host</dt>
                    <dd>{endpointHost(target.endpoint)}</dd>
                  </div>
                </dl>
              </article>
            ))}
          </div>
        ) : null}
      </SectionCard>
    </div>
  );
}
