import { useEffect, useState } from 'react';
import { ArrowLeft, Clock3, Gauge, Target as TargetIcon } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { EmptyState } from '../components/common/EmptyState';
import { StatusBadge } from '../components/common/StatusBadge';
import { mockAppService } from '../services/mockApi';
import type { Scan } from '../types';

const stageSequence = [
  'Preparing Test Cases',
  'Generating Mutations',
  'Executing Tests',
  'Analyzing Responses',
  'Classifying Findings',
  'Preserving Evidence',
  'Finalizing Report',
];

export function ScanDetailsPage() {
  const { scanId } = useParams();
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;

    mockAppService
      .getScan(scanId ?? '')
      .then((result) => {
        if (isMounted) {
          setScan(result);
        }
      })
      .finally(() => {
        if (isMounted) {
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [scanId]);

  useEffect(() => {
    if (!scan || scan.status !== 'Running') {
      return;
    }

    const interval = window.setInterval(() => {
      setScan((current) => {
        if (!current || current.status !== 'Running') {
          return current;
        }

        const nextSeconds = (current.elapsedSeconds ?? 0) + 1;
        const nextProgress = Math.min(98, Math.round((nextSeconds / 180) * 100));
        const stageIndex = Math.min(stageSequence.length - 1, Math.floor(nextSeconds / 24));

        return {
          ...current,
          elapsedSeconds: nextSeconds,
          progress: nextProgress,
          currentStage: stageSequence[stageIndex],
          testsCompleted: Math.min(current.testsTotal, current.testsCompleted + 2),
          findingsCount: Math.min(current.findingsCount + (nextSeconds % 18 === 0 ? 1 : 0), current.testsTotal),
          duration: new Date(nextSeconds * 1000).toISOString().slice(14, 19),
        };
      });
    }, 1000);

    return () => window.clearInterval(interval);
  }, [scan]);

  const handleCancel = async () => {
    if (!scan) {
      return;
    }

    const updated = await mockAppService.cancelScan(scan.scanId);
    if (updated) {
      setScan(updated);
    }
  };

  if (loading) {
    return <div className="page-loading">Loading scan details…</div>;
  }

  if (!scan) {
    return (
      <EmptyState
        title="Scan not found"
        description="The requested scan record is not available in the mock dataset."
        action={
          <Link to="/scans/history" className="primary-button">
            <ArrowLeft size={14} />
            Return to history
          </Link>
        }
      />
    );
  }

  return (
    <div className="content-stack">
      <div className="detail-header">
        <div>
          <div className="eyebrow">Assessment details</div>
          <h2>{scan.scanId}</h2>
        </div>
        <div className="button-row">
          <button type="button" className="secondary-button" onClick={handleCancel} disabled={scan.status === 'Cancelled' || scan.status === 'Completed' || scan.status === 'Failed'}>
            Cancel scan
          </button>
          <Link to="/scans/history" className="secondary-button">
            <ArrowLeft size={14} />
            Back to scan history
          </Link>
        </div>
      </div>

      <section className="section-card">
        <div className="detail-summary-grid">
          <div>
            <p className="muted-label">Scan</p>
            <h3>{scan.name ?? scan.target}</h3>
          </div>
          <div>
            <p className="muted-label">Target</p>
            <div className="inline-row">
              <TargetIcon size={14} />
              <span>{scan.target}</span>
            </div>
          </div>
          <div>
            <p className="muted-label">Status</p>
            <StatusBadge status={scan.status} />
          </div>
          <div>
            <p className="muted-label">Tests</p>
            <span>{scan.testsCompleted}/{scan.testsTotal}</span>
          </div>
          <div>
            <p className="muted-label">Findings</p>
            <span>{scan.findingsCount}</span>
          </div>
          <div>
            <p className="muted-label">Duration</p>
            <div className="inline-row">
              <Clock3 size={14} />
              <span>{scan.duration}</span>
            </div>
          </div>
        </div>
      </section>

      <div className="two-column-grid">
        <section className="section-card">
          <div className="section-card__header">
            <div>
              <h2>Configuration</h2>
              <p>Selected categories and runtime profile.</p>
            </div>
          </div>
          <div className="detail-list">
            <div><span>Categories</span><strong>{(scan.categories ?? []).join(', ') || 'Not specified'}</strong></div>
            <div><span>Profile</span><strong>{scan.profile ?? 'Standard'}</strong></div>
            <div><span>Request timeout</span><strong>{scan.timeout ?? 60}s</strong></div>
            <div><span>Delay / rate control</span><strong>{scan.delayMs ?? 250} ms</strong></div>
          </div>
        </section>

        <section className="section-card">
          <div className="section-card__header">
            <div>
              <h2>Execution summary</h2>
              <p>Observed scan runtime details.</p>
            </div>
          </div>
          <div className="detail-list">
            <div><span>Started</span><strong>{new Date(scan.startedAt).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' })}</strong></div>
            <div><span>Ended</span><strong>{scan.endedAt ? new Date(scan.endedAt).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' }) : 'In progress'}</strong></div>
            <div><span>Progress</span><strong>{scan.progress ?? 0}%</strong></div>
            <div><span>Current stage</span><strong>{scan.currentStage ?? 'Preparing Test Cases'}</strong></div>
          </div>
        </section>
      </div>

      <section className="section-card">
        <div className="section-card__header">
          <div>
            <h2>Scan evidence</h2>
            <p>Demo-safe metadata captured for this execution.</p>
          </div>
        </div>
        <div className="scan-evidence-box">
          <div className="scan-evidence-box__header">
            <Gauge size={15} />
            <span>Prepared for review</span>
          </div>
          <p>
            Synthetic evidence has been recorded for this assessment without exposing real credentials,
            production tokens, or user data.
          </p>
        </div>
      </section>
    </div>
  );
}
