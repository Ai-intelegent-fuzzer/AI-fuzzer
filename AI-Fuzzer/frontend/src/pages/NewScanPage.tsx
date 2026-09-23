import { Play, ShieldAlert, ShieldCheck } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ProgressBar } from '../components/common/ProgressBar';
import { SectionCard } from '../components/common/SectionCard';
import { mockAppService } from '../services/mockApi';
import type { ScanProfile, Target, VulnerabilityCategory } from '../types';

const categoryOptions: VulnerabilityCategory[] = [
  'Prompt Injection',
  'Jailbreak',
  'Context Poisoning',
  'Data Leakage',
];

const profileLabels: ScanProfile[] = ['Quick', 'Standard', 'Comprehensive'];

export function NewScanPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [targetId, setTargetId] = useState('');
  const [categories, setCategories] = useState<VulnerabilityCategory[]>(categoryOptions);
  const [profile, setProfile] = useState<ScanProfile>('Standard');
  const [timeout, setTimeout] = useState(90);
  const [delayMs, setDelayMs] = useState(180);
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    mockAppService.getTargets().then((items) => {
      setTargets(items);
      if (items[0]) {
        setTargetId(items[0].targetId);
      }
    });
  }, []);

  const selectedTarget = targets.find((item) => item.targetId === targetId) ?? targets[0];
  const isReady = Boolean(targetId) && categories.length > 0 && authorizationConfirmed && !isSubmitting;

  const toggleCategory = (category: VulnerabilityCategory) => {
    setCategories((current) => {
      if (current.includes(category)) {
        return current.filter((item) => item !== category);
      }
      return [...current, category];
    });
  };

  const handleSelectAll = () => {
    setCategories(categoryOptions);
  };

  const handleStartScan = async () => {
    if (!selectedTarget) {
      return;
    }

    setIsSubmitting(true);
    const created = await mockAppService.startScan({
      targetId: selectedTarget.targetId,
      name: `${selectedTarget.name} ${profile.toLowerCase()} validation`,
      categories,
      profile,
      timeout,
      delayMs,
    });

    navigate(`/scans/${created.scanId}`);
  };

  return (
    <div className="content-stack">
      <SectionCard title="New Security Scan" subtitle="Configure an authorized assessment for a target AI system">
        <div className="scan-layout">
          <div className="scan-form">
            <label>
              Target
              <select value={targetId} onChange={(event) => setTargetId(event.target.value)}>
                {targets.map((target) => (
                  <option key={target.targetId} value={target.targetId}>{target.name}</option>
                ))}
              </select>
            </label>

            <label>
              Profile
              <select value={profile} onChange={(event) => setProfile(event.target.value as ScanProfile)}>
                {profileLabels.map((option) => (
                  <option key={option} value={option}>{option}</option>
                ))}
              </select>
            </label>

            <div className="checkbox-group">
              <div className="checkbox-group__header">
                <h3>Vulnerability categories</h3>
                <button type="button" className="text-button" onClick={handleSelectAll}>Select all</button>
              </div>
              {categoryOptions.map((category) => (
                <label key={category} className="checkbox-row">
                  <input type="checkbox" checked={categories.includes(category)} onChange={() => toggleCategory(category)} />
                  <span>{category}</span>
                </label>
              ))}
            </div>

            <label>
              Request timeout: {timeout}s
              <input type="range" min="30" max="180" step="10" value={timeout} onChange={(event) => setTimeout(Number(event.target.value))} />
            </label>

            <label>
              Request rate delay: {delayMs} ms
              <input type="range" min="40" max="500" step="10" value={delayMs} onChange={(event) => setDelayMs(Number(event.target.value))} />
            </label>

            <label className="checkbox-row checkbox-row--warning">
              <input type="checkbox" checked={authorizationConfirmed} onChange={(event) => setAuthorizationConfirmed(event.target.checked)} />
              <span>I confirm this scan is authorized for the selected target and only uses synthetic test data.</span>
            </label>

            <button type="button" className="primary-button primary-button--wide" onClick={handleStartScan} disabled={!isReady}>
              <Play size={16} />
              {isSubmitting ? 'Starting Scan...' : 'Start Scan'}
            </button>
          </div>

          <div className="scan-summary">
            <div className="scan-summary__panel">
              <div className="scan-summary__row">
                <ShieldCheck size={16} />
                <span>Connection check</span>
                <strong>{selectedTarget ? 'Passed' : 'Pending'}</strong>
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
            </div>

            <div className="scan-progress">
              <h3>Scan progress</h3>
              <ProgressBar value={72} label="Detection coverage" />
              <ProgressBar value={43} label="Mutation execution" />
              <ProgressBar value={86} label="Evidence capture" />
            </div>
          </div>
        </div>
      </SectionCard>
    </div>
  );
}
