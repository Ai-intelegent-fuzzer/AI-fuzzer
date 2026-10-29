import { useEffect, useState } from 'react';
import { ExternalLink, Lock, Server, ShieldCheck } from 'lucide-react';
import { SectionCard } from '../components/common/SectionCard';
import { ApiError, apiBaseUrl, getHealth } from '../services/api';
import type { ApiHealth } from '../types';

function safeApiOrigin(value: string): string {
  if (!value) return 'Local Vite proxy to 127.0.0.1:8000';
  try {
    return new URL(value).origin;
  } catch {
    return 'Invalid backend URL';
  }
}

export function SettingsPage() {
  const [health, setHealth] = useState<ApiHealth | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [refreshKey, setRefreshKey] = useState(0);
  const docsUrl = `${apiBaseUrl || 'http://127.0.0.1:8000'}/docs`;

  useEffect(() => {
    let active = true;
    getHealth()
      .then((result) => {
        if (active) setHealth(result);
      })
      .catch((requestError: unknown) => {
        if (active) {
          setError(requestError instanceof ApiError ? requestError.message : 'Backend health check failed.');
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => { active = false; };
  }, [refreshKey]);

  return (
    <div className="content-stack">
      <SectionCard title="Platform Settings" subtitle="Verified connection details and integration limits">
        <div className="settings-grid">
          <div className="settings-item">
            <div className="settings-item__icon"><Server size={16} /></div>
            <div>
              <h3>Backend URL</h3>
              <p>{safeApiOrigin(apiBaseUrl)}</p>
            </div>
          </div>
          <div className="settings-item">
            <div className="settings-item__icon"><ShieldCheck size={16} /></div>
            <div>
              <h3>Health endpoint</h3>
              <p>{loading ? 'Checking…' : error || health?.status || 'No health status returned.'}</p>
              {error ? (
                <button type="button" className="text-button" onClick={() => {
                  setLoading(true);
                  setError('');
                  setRefreshKey((key) => key + 1);
                }} disabled={loading}>
                  Retry
                </button>
              ) : null}
            </div>
          </div>
          <div className="settings-item">
            <div className="settings-item__icon"><Lock size={16} /></div>
            <div>
              <h3>Read-only frontend integration</h3>
              <p>Scan creation, cancellation, target mutation, and connectivity probes are not enabled in this frontend.</p>
            </div>
          </div>
          <div className="settings-item">
            <div className="settings-item__icon"><ExternalLink size={16} /></div>
            <div>
              <h3>Backend API documentation</h3>
              <p>
                <a href={docsUrl} target="_blank" rel="noreferrer">Open FastAPI docs</a>
              </p>
            </div>
          </div>
        </div>
        <p className="muted-label">
          The backend currently keeps target and scan data in process memory. This frontend does not imply
          authentication, persistent storage, or server-side authorization protections.
        </p>
      </SectionCard>
    </div>
  );
}
