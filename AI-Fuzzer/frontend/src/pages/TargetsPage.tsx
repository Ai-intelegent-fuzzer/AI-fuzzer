import { ArrowUpRight, Plus, Target as TargetIcon, Trash2, Wifi } from 'lucide-react';
import { useEffect, useState } from 'react';
import { SectionCard } from '../components/common/SectionCard';
import { mockAppService } from '../services/mockApi';
import type { Target, TargetDraft } from '../types';

const emptyForm: TargetDraft = {
  name: '',
  type: 'LLM API',
  endpoint: '',
  authType: 'API Key',
  modelName: '',
  description: '',
};

export function TargetsPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<TargetDraft>(emptyForm);
  const [error, setError] = useState('');
  const [connectionStatus, setConnectionStatus] = useState<{ status: string; message: string } | null>(null);
  const [isTesting, setIsTesting] = useState(false);
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    mockAppService.getTargets().then(setTargets);
  }, []);

  const handleChange = (field: keyof TargetDraft, value: string) => {
    setForm((current) => ({ ...current, [field]: value }));
    setError('');
    setConnectionStatus(null);
  };

  const handleTestConnection = async () => {
    if (!form.name.trim() || !form.endpoint.trim()) {
      setError('Name and endpoint are required before testing the mock connection.');
      return;
    }

    setIsTesting(true);
    setError('');
    const result = await mockAppService.testTargetConnection({
      name: form.name,
      endpoint: form.endpoint,
    });
    setConnectionStatus(result);
    setIsTesting(false);
  };

  const handleSaveTarget = async () => {
    if (!form.name.trim() || !form.endpoint.trim()) {
      setError('Target name and endpoint must be provided before saving.');
      return;
    }

    setIsSaving(true);
    setError('');
    const created = await mockAppService.createTarget(form);
    setTargets((current) => [created, ...current]);
    setForm(emptyForm);
    setShowForm(false);
    setConnectionStatus(null);
    setIsSaving(false);
  };

  const handleDeleteTarget = async (targetId: string) => {
    const target = targets.find((item) => item.targetId === targetId);
    if (!target) {
      return;
    }

    const confirmed = window.confirm(`Remove ${target.name} from the authorized target list?`);
    if (!confirmed) {
      return;
    }

    await mockAppService.removeTarget(targetId);
    setTargets((current) => current.filter((item) => item.targetId !== targetId));
  };

  return (
    <div className="content-stack">
      <SectionCard
        title="Authorized Targets"
        subtitle="Configured AI endpoints available for assessment"
        action={
          <button type="button" className="primary-button" onClick={() => setShowForm((current) => !current)}>
            <Plus size={14} />
            {showForm ? 'Close' : 'Add Target'}
          </button>
        }
      >
        {showForm ? (
          <div className="form-panel">
            <div className="form-grid">
              <label className="field-group">
                <span>Target name</span>
                <input type="text" value={form.name} onChange={(event) => handleChange('name', event.target.value)} placeholder="Customer Support AI" />
              </label>

              <label className="field-group">
                <span>Target type</span>
                <select value={form.type} onChange={(event) => handleChange('type', event.target.value)}>
                  <option value="LLM API">LLM API</option>
                  <option value="AI Chatbot">AI Chatbot</option>
                  <option value="RAG Application">RAG Application</option>
                  <option value="AI Agent">AI Agent</option>
                </select>
              </label>

              <label className="field-group field-group--full">
                <span>Endpoint URL</span>
                <input type="text" value={form.endpoint} onChange={(event) => handleChange('endpoint', event.target.value)} placeholder="https://api.example.internal/support-ai" />
              </label>

              <label className="field-group">
                <span>Authentication</span>
                <select value={form.authType} onChange={(event) => handleChange('authType', event.target.value)}>
                  <option value="None">None</option>
                  <option value="API Key">API Key</option>
                  <option value="Bearer Token">Bearer Token</option>
                </select>
              </label>

              <label className="field-group">
                <span>Model name</span>
                <input type="text" value={form.modelName} onChange={(event) => handleChange('modelName', event.target.value)} placeholder="gpt-4o-mini" />
              </label>

              <label className="field-group field-group--full">
                <span>Description</span>
                <textarea value={form.description} onChange={(event) => handleChange('description', event.target.value)} rows={3} placeholder="Describe the purpose and deployment context of this secure target." />
              </label>
            </div>

            {error ? <div className="inline-message inline-message--error">{error}</div> : null}
            {connectionStatus ? (
              <div className={`inline-message ${connectionStatus.status === 'Connection Failed' ? 'inline-message--error' : 'inline-message--success'}`}>
                <strong>{connectionStatus.status}</strong>
                <span>{connectionStatus.message}</span>
              </div>
            ) : null}

            <div className="button-row">
              <button type="button" className="secondary-button" onClick={handleTestConnection} disabled={isTesting}>
                <Wifi size={14} />
                {isTesting ? 'Testing...' : 'Test Connection'}
              </button>
              <button type="button" className="primary-button" onClick={handleSaveTarget} disabled={isSaving}>
                {isSaving ? 'Saving...' : 'Save Target'}
              </button>
            </div>
          </div>
        ) : null}

        <div className="target-grid">
          {targets.map((target) => (
            <article key={target.targetId} className="target-card">
              <div className="target-card__header">
                <div className="target-card__icon">
                  <TargetIcon size={18} />
                </div>
                <div>
                  <h3>{target.name}</h3>
                  <p>{target.type}</p>
                </div>
              </div>

              <div className="target-card__meta">
                <span className={`status-mini status-mini--${target.status.toLowerCase()}`}>
                  {target.status}
                </span>
                <span className="risk-pill risk-pill--medium">{target.riskProfile}</span>
              </div>

              <dl className="target-card__details">
                <div>
                  <dt>Target ID</dt>
                  <dd className="mono-text">{target.targetId}</dd>
                </div>
                <div>
                  <dt>Endpoint</dt>
                  <dd>{target.endpoint}</dd>
                </div>
                <div>
                  <dt>Authentication</dt>
                  <dd>{target.authType ?? 'None'}</dd>
                </div>
                <div>
                  <dt>Last tested</dt>
                  <dd>{new Date(target.lastTested).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' })}</dd>
                </div>
              </dl>

              <div className="button-row button-row--stacked">
                <button type="button" className="secondary-button">
                  <ArrowUpRight size={14} />
                  Review configuration
                </button>
                <button type="button" className="icon-button" onClick={() => handleDeleteTarget(target.targetId)} aria-label={`Delete ${target.name}`}>
                  <Trash2 size={14} />
                </button>
              </div>
            </article>
          ))}
        </div>
      </SectionCard>
    </div>
  );
}
