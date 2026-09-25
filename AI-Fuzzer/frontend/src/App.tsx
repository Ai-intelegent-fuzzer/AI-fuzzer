import { BrowserRouter, matchPath, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { AppShell } from './components/layout/AppShell';
import { DashboardPage } from './pages/DashboardPage';
import { FindingDetailPage } from './pages/FindingDetailPage';
import { FindingsPage } from './pages/FindingsPage';
import { NewScanPage } from './pages/NewScanPage';
import { ReportDetailPage } from './pages/ReportDetailPage';
import { ReportsPage } from './pages/ReportsPage';
import { ScanDetailsPage } from './pages/ScanDetailsPage';
import { ScanHistoryPage } from './pages/ScanHistoryPage';
import { SettingsPage } from './pages/SettingsPage';
import { TargetsPage } from './pages/TargetsPage';
import './App.css';

const pageMeta: Record<string, { title: string; subtitle: string }> = {
  '/dashboard': {
    title: 'Dashboard',
    subtitle: 'Monitor AI security scans, vulnerabilities, and testing activity.',
  },
  '/targets': {
    title: 'Targets',
    subtitle: 'Authorized AI endpoints and risk posture overview.',
  },
  '/scans/new': {
    title: 'New Scan',
    subtitle: 'Configure and initiate a new AI security assessment.',
  },
  '/scans/history': {
    title: 'Scan History',
    subtitle: 'Review prior security assessments and execution outcomes.',
  },
  '/findings': {
    title: 'Findings',
    subtitle: 'Evidence-backed vulnerability details and remediation guidance.',
  },
  '/findings/:findingId': {
    title: 'Finding Detail',
    subtitle: 'Evidence review and forensics for the selected vulnerability.',
  },
  '/reports': {
    title: 'Reports',
    subtitle: 'Exportable security reports for executive and technical review.',
  },
  '/reports/:reportId': {
    title: 'Report Detail',
    subtitle: 'Detailed assessment summary with JSON export and print options.',
  },
  '/settings': {
    title: 'Settings',
    subtitle: 'Operational preferences and platform controls.',
  },
};

function AppContent() {
  const location = useLocation();
  const meta = Object.entries(pageMeta).find(([path]) => matchPath({ path, end: true }, location.pathname))?.[1] ?? pageMeta['/dashboard'];

  return (
    <AppShell title={meta.title} subtitle={meta.subtitle}>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/targets" element={<TargetsPage />} />
        <Route path="/scans/new" element={<NewScanPage />} />
        <Route path="/scans/history" element={<ScanHistoryPage />} />
        <Route path="/scans/:scanId" element={<ScanDetailsPage />} />
        <Route path="/findings" element={<FindingsPage />} />
        <Route path="/findings/:findingId" element={<FindingDetailPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/reports/:reportId" element={<ReportDetailPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </AppShell>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  );
}
