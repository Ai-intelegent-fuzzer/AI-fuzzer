import { Link, useNavigate } from 'react-router-dom';
import { Play, ShieldAlert, ShieldCheck } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { SectionCard } from '../components/common/SectionCard';
import { apiClient } from '../services/api';
import type { ApiAttackCategory, Target } from '../types';

export function NewScanPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [categories, setCategories] = useState<ApiAttackCategory[]>([]);
  const [selectedCategories, setSelectedCategories] = useState<string[]>([]);
  const [benchmarkId, setBenchmarkId] = useState<string | undefined>();
  const [targetId, setTargetId] = useState('');
  const [count, setCount] = useState(5);
  const [timeoutSeconds, setTimeoutSeconds] = useState(30);
  const [delayMs, setDelayMs] = useState(180);
  const [connectionMessage, setConnectionMessage] = useState('');
  const [connectionPassed, setConnectionPassed] = useState(false);
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [isTesting, setIsTesting] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    apiClient.getTargets()
      .then(async (targetItems) => {
        setTargets(targetItems);
        const initialTarget = targetItems[0];
        if (initialTarget) setTargetId(initialTarget.targetId);
        const categoryItems = await apiClient.getAttackCategories(initialTarget?.targetId);
        setCategories(categoryItems);
        setSelectedCategories(categoryItems
          .filter((category) => category.applicable)
          .map((category) => category.category));
      })
      .catch((cause: unknown) => setError(cause instanceof Error ? cause.message : 'Unable to load scan configuration.'))
      .finally(() => setIsLoading(false));
  }, []);

  const selectedTarget = useMemo(() => targets.find((target) => target.targetId === targetId), [targets, targetId]);
  const isReady = Boolean(selectedTarget && selectedCategories.length && connectionPassed && authorizationConfirmed)
    && !isSubmitting && !isTesting;

  const changeTarget = async (id: string) => {
    setTargetId(id);
    setConnectionPassed(false);
    setConnectionMessage('');
    setError('');
    try {
      const targetCategories = await apiClient.getAttackCategories(id);
      setCategories(targetCategories);
      setSelectedCategories(targetCategories
        .filter((category) => category.applicable)
        .map((category) => category.category));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to load target-specific categories.');
    }
  };

  const toggleCategory = (category: string) => {
    setBenchmarkId(undefined);
    setSelectedCategories((current) => current.includes(category)
      ? current.filter((value) => value !== category)
      : [...current, category]);
  };

  const selectPromptInjectionBenchmark = async () => {
    try {
      const benchmark = (await apiClient.getBenchmarks()).find((item) => item.benchmark_id === 'prompt_injection_180');
      if (!benchmark) throw new Error('Prompt-injection benchmark is unavailable.');
      setBenchmarkId(benchmark.benchmark_id);
      setCount(benchmark.case_count);
      setSelectedCategories(benchmark.categories);
      setError('');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to load benchmark.');
    }
  };

  const testConnection = async () => {
    if (!selectedTarget) return;
    if (!authorizationConfirmed) {
      setError('Confirm authorization before testing the target connection.');
      return;
    }
    setIsTesting(true);
    setError('');
    setConnectionMessage('');
    setConnectionPassed(false);
    try {
      const result = await apiClient.testTargetConnection(selectedTarget.targetId, authorizationConfirmed);
      setConnectionPassed(result.status === 'Connection Successful');
      setConnectionMessage(result.message);
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : 'Connectivity test failed.';
      setConnectionMessage(message);
      setError(message);
    } finally {
      setIsTesting(false);
    }
  };

  const handleStartScan = async () => {
    if (!selectedTarget) {
      setError('Select an authorized target before starting a scan.');
      return;
    }
    if (count < 1 || count > 1000) {
      setError('Scan count must be between 1 and 1000.');
      return;
    }
    if (!selectedCategories.length) {
      setError('Select at least one supported test category.');
      return;
    }
    if (!connectionPassed || !authorizationConfirmed) {
      setError('Test connectivity and confirm authorization before starting.');
      return;
    }

    setIsSubmitting(true);
    setError('');
    try {
      const created = await apiClient.startScan({
        targetId: selectedTarget.targetId,
        count,
        categories: selectedCategories,
        timeout: timeoutSeconds,
        delayMs,
        authorizationConfirmed,
        benchmarkId,
      });
      navigate(`/scans/${created.scanId}`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to start scan.');
      setIsSubmitting(false);
    }
  };

  if (isLoading) {
    return <div className="page-loading">Loading scan configuration…</div>;
  }

  return (
    <div className="content-stack">
      <SectionCard title="New Security Scan" subtitle="Configure an authorized assessment for a registered AI target">
        <div className="scan-layout">
          <div className="scan-form">
            {error ? <div className="inline-message inline-message--error" role="alert">{error}</div> : null}
            {targets.length === 0 ? (
              <div className="inline-message inline-message--error">
                <span>No authorized targets are registered.</span>
                <Link to="/targets" className="inline-link">Add a target</Link>
              </div>
            ) : null}

            <label>
              Target
              <select value={targetId} onChange={(event) => changeTarget(event.target.value)} disabled={!targets.length}>
                {targets.map((target) => <option key={target.targetId} value={target.targetId}>{target.name}</option>)}
              </select>
            </label>

            {selectedTarget ? (
              <>
                <p className="muted-label">
                  Provider: {selectedTarget.provider ?? 'openai'} · Model: {selectedTarget.modelName || 'not configured'}
                </p>
              <div className="button-row">
                <button type="button" className="secondary-button" onClick={testConnection} disabled={isTesting || !authorizationConfirmed}>
                  <ShieldCheck size={16} />
                  {isTesting ? 'Testing connection…' : 'Test target connection'}
                </button>
                {connectionMessage ? (
                  <span className={connectionPassed ? 'inline-success-text' : 'inline-error-text'}>{connectionMessage}</span>
                ) : null}
              </div>
              </>
            ) : null}

            <label>
              Total test cases (including mutations)
              <input type="number" min="1" max="1000" step="1" value={count} onChange={(event) => { setBenchmarkId(undefined); setCount(Number(event.target.value)); }} />
            </label>
            <button type="button" className="secondary-button" onClick={selectPromptInjectionBenchmark}>
              Run 180-case prompt-injection benchmark
            </button>
            {benchmarkId ? <p className="muted-label">Selected benchmark: {benchmarkId} · sequential, concurrency 1</p> : null}
            {count > 0 && selectedCategories.length > count ? (
              <div className="inline-message inline-message--warning" role="status">
                This scan requests {count} total test case(s) across {selectedCategories.length} categories.
                At most {count} selected categories can receive a base case; the report will show actual coverage.
              </div>
            ) : null}

            <div className="checkbox-group">
              <div className="checkbox-group__header">
                <h3>Supported test categories</h3>
                <button
                  type="button"
                  className="text-button"
                  onClick={() => setSelectedCategories(categories
                    .filter((category) => category.applicable)
                    .map((category) => category.category))}
                >
                  Select all applicable
                </button>
              </div>
              {categories.map((category) => (
                <label key={category.category} className="checkbox-row">
                  <input
                    type="checkbox"
                    checked={selectedCategories.includes(category.category)}
                    disabled={!category.applicable}
                    onChange={() => toggleCategory(category.category)}
                  />
                  <span>
                    {category.category.replace(/_/g, ' ')}
                    {!category.applicable ? ' · not applicable to this target' : ''}
                  </span>
                </label>
              ))}
            </div>

            <label>
              Request timeout: {timeoutSeconds}s
              <input type="range" min="1" max="120" step="1" value={timeoutSeconds} onChange={(event) => setTimeoutSeconds(Number(event.target.value))} />
            </label>

            <label>
              Request delay: {delayMs} ms
              <input type="range" min="0" max="10000" step="100" value={delayMs} onChange={(event) => setDelayMs(Number(event.target.value))} />
            </label>

            <label className="checkbox-row checkbox-row--warning">
              <input type="checkbox" checked={authorizationConfirmed} onChange={(event) => setAuthorizationConfirmed(event.target.checked)} />
              <span>I confirm I am authorized to assess this target and will use the scan only within that authorization.</span>
            </label>

            <button type="button" className="primary-button primary-button--wide" onClick={handleStartScan} disabled={!isReady}>
              <Play size={16} />
              {isSubmitting ? 'Starting Scan…' : 'Start Scan'}
            </button>
          </div>

          <div className="scan-summary">
            <div className="scan-summary__panel">
              <div className="scan-summary__row">
                <ShieldCheck size={16} />
                <span>Connection check</span>
                <strong>{connectionPassed ? 'Passed' : selectedTarget ? 'Required' : 'Unavailable'}</strong>
              </div>
              <div className="scan-summary__row">
                <ShieldAlert size={16} />
                <span>Authorization</span>
                <strong>{authorizationConfirmed ? 'Confirmed' : 'Required'}</strong>
              </div>
              <div className="scan-summary__row">
                <span className="muted-label">Selected target</span>
                <strong>{selectedTarget?.name ?? 'None'}</strong>
              </div>
              <div className="scan-summary__row">
                <span className="muted-label">Selected categories</span>
                <strong>{selectedCategories.length}</strong>
              </div>
            </div>
            <p className="muted-label">Execution uses the backend scan scheduler and existing fuzzing, execution, and analysis pipeline. Status and results are fetched from the backend.</p>
          </div>
        </div>
      </SectionCard>
    </div>
  );
}
