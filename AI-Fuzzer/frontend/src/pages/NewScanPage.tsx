import { AlertTriangle, ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import { SectionCard } from '../components/common/SectionCard';

export function NewScanPage() {
  return (
    <div className="content-stack">
      <SectionCard title="Scan Execution Unavailable" subtitle="This frontend is connected in read-only mode">
        <div className="detail-block detail-block--stacked">
          <div className="detail-block__icon detail-block__icon--danger"><AlertTriangle size={16} /></div>
          <p>
            Starting or cancelling scans is intentionally not exposed here. The backend scan endpoint
            launches automated test traffic against a configured target, so this UI does not send scan
            requests or perform connectivity probes.
          </p>
          <p>
            Existing scan records and their results can be reviewed using a scan ID. No scan is created
            by opening this page.
          </p>
          <div className="button-row">
            <Link to="/scans/history" className="primary-button">
              Look up an existing scan <ArrowRight size={14} />
            </Link>
            <Link to="/targets" className="secondary-button">View registered targets</Link>
          </div>
        </div>
      </SectionCard>
    </div>
  );
}
