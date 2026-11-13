import { ArrowUpRight, Plus, Target as TargetIcon, Trash2, Wifi } from 'lucide-react';
import { useEffect, useState } from 'react';
import { SectionCard } from '../components/common/SectionCard';
import { apiClient } from '../services/api';
import type { Target, TargetDraft } from '../types';

const emptyForm: TargetDraft = {
  name: '',
  type: 'LLM API',
  provider: 'openai',
  endpoint: '',
  authType: 'API Key',
  apiKey: '',
  modelName: '',
  description: '',
  apiPath: '',
  authHeader: 'Authorization',
  systemPrompt: '',
  temperature: 0,
  maxOutputTokens: 256,
};

export function TargetsPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [editingTargetId, setEditingTargetId] = useState('');
  const [form, setForm] = useState<TargetDraft>(emptyForm);
  const [error, setError] = useState('');
  const [connectionStatus, setConnectionStatus] = useState<Record<string, { status: string; message: string }>>({});
  const [testingTargetId, setTestingTargetId] = useState('');
  const [isSaving, setIsSaving] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiClient.getTargets()
      .then(setTargets)
      .catch((cause: unknown) => setError(cause instanceof Error ? cause.message : 'Unable to load targets.'))
      .finally(() => setLoading(false));
  }, []);

  const handleChange = (field: keyof TargetDraft, value: string) => {
    setForm((current) => ({ ...current, [field]: value }));
    setError('');
  };

  const handleTestConnection = async (targetId: string) => {
    const target = targets.find((item) => item.targetId === targetId);
    if (!target || !window.confirm(`Confirm that you are authorized to test ${target.name}?`)) return;
    setTestingTargetId(targetId);
    setError('');
    try {
      const result = await apiClient.testTargetConnection(targetId, true);
      setConnectionStatus((current) => ({ ...current, [targetId]: result }));
      setTargets((current) => current.map((target) => target.targetId === targetId
        ? {
          ...target,
          status: result.status === 'Connection Successful' ? 'Operational' : 'Offline',
          lastTested: new Date().toISOString(),
        }
        : target));
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : 'Connectivity test failed.';
      setError(message);
      setConnectionStatus((current) => ({
        ...current,
        [targetId]: { status: 'Connection Failed', message },
      }));
    } finally {
      setTestingTargetId('');
    }
  };

  const handleSaveTarget = async () => {
    if (!form.name.trim() || !form.endpoint.trim()) {
      setError('Target name and endpoint must be provided before saving.');
      return;
    }

    setIsSaving(true);
    setError('');
    try {
      const draft = { ...form, name: form.name.trim(), endpoint: form.endpoint.trim() };
      const saved = editingTargetId
        ? await apiClient.updateTarget(editingTargetId, draft)
        : await apiClient.createTarget(draft);
      setTargets((current) => editingTargetId
        ? current.map((target) => target.targetId === editingTargetId ? saved : target)
        : [saved, ...current]);
      setForm(emptyForm);
      setEditingTargetId('');
      setShowForm(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to save target.');
    } finally {
      setIsSaving(false);
    }
  };

  const handleEditTarget = (target: Target) => {
    setForm({
      name: target.name,
      type: target.type,
      provider: target.provider ?? 'openai',
      endpoint: target.endpoint,
      authType: 'API Key',
      apiKey: '',
      modelName: target.modelName ?? '',
      description: target.description ?? '',
      apiPath: target.apiPath ?? '',
      authHeader: target.authHeader ?? 'Authorization',
      systemPrompt: target.systemPrompt ?? '',
      temperature: target.temperature ?? 0,
      maxOutputTokens: target.maxOutputTokens ?? 256,
    });
    setEditingTargetId(target.targetId);
    setShowForm(true);
    setError('');
  };

  const handleDeleteCredential = async (target: Target) => {
    if (!window.confirm(`Remove the saved provider credential for ${target.name}?`)) return;
    try {
      await apiClient.deleteTargetCredential(target.targetId);
      setError('');
      setConnectionStatus((current) => ({
        ...current,
        [target.targetId]: { status: 'Credential Removed', message: 'Saved credential removed from the backend.' },
      }));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to remove the saved credential.');
    }
  };

  const handleDeleteTarget = async (targetId: string) => {
    const target = targets.find((item) => item.targetId === targetId);
    if (!target || !window.confirm(`Remove ${target.name} from the authorized target list?`)) {
      return;
    }

    setError('');
    try {
      await apiClient.removeTarget(targetId);
      setTargets((current) => current.filter((item) => item.targetId !== targetId));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to remove target.');
    }
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
        {error ? <div className="inline-message inline-message--error" role="alert">{error}</div> : null}
        {showForm ? (
          <div className="form-panel">
            <div className="form-grid">
              <label className="field-group">
                <span>Target name</span>
                <input required type="text" value={form.name} onChange={(event) => handleChange('name', event.target.value)} placeholder="Customer Support AI" />
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
                <input required type="url" value={form.endpoint} onChange={(event) => handleChange('endpoint', event.target.value)} placeholder="https://api.example.com/v1" />
              </label>

              <label className="field-group">
                <span>Provider</span>
                <select value={form.provider} onChange={(event) => handleChange('provider', event.target.value)}>
                  <option value="openai">OpenAI</option>
                  <option value="groq">Groq</option>
                  <option value="gemini">Google Gemini</option>
                  <option value="anthropic">Anthropic Claude</option>
                  <option value="mistral">Mistral AI</option>
                  <option value="ollama">Ollama (local policy required)</option>
                  <option value="custom">Custom OpenAI-compatible</option>
                </select>
              </label>

              <label className="field-group">
                <span>Model name</span>
                <input type="text" value={form.modelName} onChange={(event) => handleChange('modelName', event.target.value)} placeholder="gpt-4o-mini" />
              </label>

              <label className="field-group">
                <span>API key (optional)</span>
                <input type="password" autoComplete="new-password" value={form.apiKey ?? ''} onChange={(event) => handleChange('apiKey', event.target.value)} placeholder={editingTargetId ? 'Leave blank to keep current key' : 'Enter provider key'} />
              </label>

              <label className="field-group">
                <span>API path (optional)</span>
                <input type="text" value={form.apiPath ?? ''} onChange={(event) => handleChange('apiPath', event.target.value)} placeholder="e.g. /v1/responses or /api/chat" />
              </label>

              {form.provider === 'custom' ? (
                <label className="field-group">
                  <span>Authentication header</span>
                  <input type="text" value={form.authHeader ?? 'Authorization'} onChange={(event) => handleChange('authHeader', event.target.value)} />
                </label>
              ) : null}

              <label className="field-group">
                <span>Temperature (0–2)</span>
                <input type="number" min="0" max="2" step="0.1" value={form.temperature ?? 0} onChange={(event) => setForm((current) => ({ ...current, temperature: Number(event.target.value) }))} />
              </label>

              <label className="field-group">
                <span>Maximum output tokens</span>
                <input type="number" min="1" max="8192" step="1" value={form.maxOutputTokens ?? 256} onChange={(event) => setForm((current) => ({ ...current, maxOutputTokens: Number(event.target.value) }))} />
              </label>

              <label className="field-group field-group--full">
                <span>System prompt (optional)</span>
                <textarea value={form.systemPrompt ?? ''} onChange={(event) => handleChange('systemPrompt', event.target.value)} rows={2} />
              </label>

              <label className="field-group field-group--full">
                <span>Description</span>
                <textarea value={form.description} onChange={(event) => handleChange('description', event.target.value)} rows={3} placeholder="Describe the purpose and deployment context of this authorized target." />
              </label>
            </div>

            <p className="muted-label">Only add systems you are authorized to assess. API keys are sent to the backend for encrypted storage and are never returned by the API or stored in browser persistence.</p>
            <div className="button-row">
              <button type="button" className="primary-button" onClick={handleSaveTarget} disabled={isSaving}>
                {isSaving ? 'Saving...' : editingTargetId ? 'Update Target' : 'Save Target'}
              </button>
            </div>
          </div>
        ) : null}

        {loading ? <div className="page-loading">Loading authorized targets…</div> : null}
        {!loading && targets.length === 0 ? <p className="empty-copy">No targets are registered yet. Add an authorized target to begin.</p> : null}
        <div className="target-grid">
          {targets.map((target) => (
            <article key={target.targetId} className="target-card">
              <div className="target-card__header">
                <div className="target-card__icon"><TargetIcon size={18} /></div>
                <div>
                  <h3>{target.name}</h3>
                  <p>{target.type}</p>
                </div>
              </div>

              <div className="target-card__meta">
                <span className={`status-mini status-mini--${target.status.toLowerCase()}`}>{target.status}</span>
                <span className="risk-pill">{target.riskProfile}</span>
              </div>

              <dl className="target-card__details">
                <div><dt>Target ID</dt><dd className="mono-text">{target.targetId}</dd></div>
                <div><dt>Endpoint</dt><dd>{target.endpoint}</dd></div>
                <div><dt>Provider / model</dt><dd>{target.provider ?? 'openai'} / {target.modelName || 'Not configured'}</dd></div>
                <div>
                  <dt>Last tested</dt>
                  <dd>{target.lastTested ? new Date(target.lastTested).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' }) : 'Not tested'}</dd>
                </div>
              </dl>

              {connectionStatus[target.targetId] ? (
                <div className={`inline-message ${connectionStatus[target.targetId].status === 'Connection Failed' ? 'inline-message--error' : 'inline-message--success'}`}>
                  <strong>{connectionStatus[target.targetId].status}</strong>
                  <span>{connectionStatus[target.targetId].message}</span>
                </div>
              ) : null}

              <div className="button-row button-row--stacked">
                <button type="button" className="secondary-button" onClick={() => handleTestConnection(target.targetId)} disabled={testingTargetId === target.targetId}>
                  <Wifi size={14} />
                  {testingTargetId === target.targetId ? 'Testing...' : 'Test Connection'}
                </button>
                <button type="button" className="secondary-button" onClick={() => handleEditTarget(target)}>
                  <ArrowUpRight size={14} />
                  Edit configuration
                </button>
                <button type="button" className="secondary-button" onClick={() => handleDeleteCredential(target)}>Remove saved key</button>
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
