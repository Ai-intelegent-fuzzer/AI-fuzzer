import { useEffect, useMemo, useState } from 'react';
import { Save } from 'lucide-react';
import { SectionCard } from '../components/common/SectionCard';
import { apiClient } from '../services/api';
import type {
  ApiCapabilityProfile,
  ApiCapabilitySetting,
  CapabilityName,
  Target,
} from '../types';

const capabilityNames: CapabilityName[] = [
  'model_endpoint',
  'web_application',
  'rag_enabled',
  'vector_database',
  'tool_calling',
  'mcp_enabled',
  'authentication_enabled',
  'authorization_enabled',
  'multi_tenant',
  'agent_memory',
  'external_integrations',
];

const defaultSetting: ApiCapabilitySetting = {
  enabled: false,
  validation_status: 'not_configured',
  supported_security_tests: [],
  known_limitations: [],
};

function normalizedName(value: string) {
  return value.replace(/_/g, ' ');
}

export function CapabilitiesPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [targetId, setTargetId] = useState('');
  const [profile, setProfile] = useState<ApiCapabilityProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [saved, setSaved] = useState(false);
  const selectedTarget = useMemo(
    () => targets.find((target) => target.targetId === targetId),
    [targets, targetId],
  );

  useEffect(() => {
    apiClient.getTargets()
      .then((items) => {
        setTargets(items);
        setTargetId(items[0]?.targetId ?? '');
        setProfile(items[0]?.capabilityProfile ?? null);
      })
      .catch((cause: unknown) => setError(
        cause instanceof Error ? cause.message : 'Unable to load target capability profiles.',
      ))
      .finally(() => setLoading(false));
  }, []);

  const selectTarget = (id: string) => {
    setTargetId(id);
    setProfile(targets.find((target) => target.targetId === id)?.capabilityProfile ?? null);
    setSaved(false);
  };

  const updateSetting = (
    capability: CapabilityName,
    update: Partial<ApiCapabilitySetting>,
  ) => {
    setProfile((current) => {
      if (!current) return current;
      const setting = current.capabilities[capability] ?? defaultSetting;
      return {
        capabilities: {
          ...current.capabilities,
          [capability]: { ...setting, ...update },
        },
      };
    });
    setSaved(false);
  };

  const save = async () => {
    if (!targetId || !profile) return;
    setSaving(true);
    setError('');
    setSaved(false);
    try {
      const updated = await apiClient.updateTargetCapabilities(targetId, profile);
      setTargets((current) => current.map((target) => (
        target.targetId === targetId ? updated : target
      )));
      setProfile(updated.capabilityProfile ?? profile);
      setSaved(true);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to update the capability profile.');
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <div className="page-loading">Loading capability profiles…</div>;

  return (
    <div className="content-stack">
      <SectionCard
        title="Target capability profiles"
        subtitle="Capabilities gate application-level tests; configured profiles do not imply independent verification."
        action={(
          <button type="button" className="primary-button" onClick={save} disabled={!profile || saving}>
            <Save size={14} />{saving ? 'Saving…' : 'Save profile'}
          </button>
        )}
      >
        {error ? <div className="inline-message inline-message--error" role="alert">{error}</div> : null}
        {saved ? <div className="inline-message inline-message--success" role="status">Capability profile saved.</div> : null}
        {!targets.length ? <p className="empty-copy">Add an authorized target before configuring capabilities.</p> : (
          <>
            <label className="field-group">
              <span>Target</span>
              <select value={targetId} onChange={(event) => selectTarget(event.target.value)}>
                {targets.map((target) => (
                  <option key={target.targetId} value={target.targetId}>{target.name}</option>
                ))}
              </select>
            </label>
            <p className="muted-label">
              Scope: {selectedTarget?.targetScope?.replace(/_/g, ' ') ?? 'unknown'}
              {' · '}enabled features can only be scanned where their target scope and validation state permit.
            </p>
            {profile ? (
              <div className="capability-list">
                {capabilityNames.map((name) => {
                  const setting = profile.capabilities[name] ?? defaultSetting;
                  return (
                    <article key={name} className="capability-row">
                      <div className="capability-row__heading">
                        <div>
                          <h3>{normalizedName(name)}</h3>
                          <p>{setting.known_limitations.join(' ') || 'No limitations recorded.'}</p>
                        </div>
                        <label className="checkbox-row">
                          <input
                            type="checkbox"
                            checked={setting.enabled}
                            onChange={(event) => updateSetting(name, {
                              enabled: event.target.checked,
                              validation_status: event.target.checked
                                && setting.validation_status === 'not_configured'
                                ? 'configured'
                                : setting.validation_status,
                            })}
                          />
                          <span>Enabled</span>
                        </label>
                      </div>
                      <div className="form-grid">
                        <label className="field-group">
                          <span>Validation status</span>
                          <select
                            value={setting.validation_status}
                            onChange={(event) => updateSetting(name, {
                              validation_status: event.target.value as ApiCapabilitySetting['validation_status'],
                            })}
                          >
                            {(['not_configured', 'unverified', 'configured', 'verified', 'invalid'] as const)
                              .filter((status) => !setting.enabled || !['not_configured', 'invalid'].includes(status))
                              .map((status) => <option key={status} value={status}>{normalizedName(status)}</option>)}
                          </select>
                        </label>
                        <label className="field-group">
                          <span>Configuration reference</span>
                          <input
                            maxLength={200}
                            value={setting.configuration_reference ?? ''}
                            onChange={(event) => updateSetting(name, {
                              configuration_reference: event.target.value || null,
                            })}
                            placeholder="Optional synthetic reference"
                          />
                        </label>
                      </div>
                      {setting.supported_security_tests.length ? (
                        <p className="muted-label">
                          Supported tests: {setting.supported_security_tests.map(normalizedName).join(', ')}
                        </p>
                      ) : null}
                    </article>
                  );
                })}
              </div>
            ) : <p className="empty-copy">No capability profile is available for this target.</p>}
          </>
        )}
      </SectionCard>
    </div>
  );
}
