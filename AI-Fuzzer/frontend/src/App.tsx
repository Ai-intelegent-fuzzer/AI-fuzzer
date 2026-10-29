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
    subtitle: 'Live backend health and registered target inventory.',
  },
  '/targets': {
    title: 'Targets',
    subtitle: 'Read-only view of targets registered in the backend.',
  },
  '/scans/new': {
    title: 'New Scan',
    subtitle: 'Scan initiation is not enabled in this read-only frontend integration.',
  },
  '/scans/history': {
    title: 'Scan History',
    subtitle: 'Look up scan details and results using a backend scan ID.',
  },
  '/scans/:scanId': {
    title: 'Scan Details',
    subtitle: 'Backend-reported scan status, metrics, and results.',
  },
  '/findings': {
    title: 'Findings',
    subtitle: 'Analyzer findings and evidence from retrieved scan results.',
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
        <Route path="/scans/:scanId" element={<ScanDetailsPage key={location.pathname} />} />
        <Route path="/findings" element={<FindingsPage />} />
        <Route path="/findings/:findingId" element={<FindingDetailPage key={`${location.pathname}${location.search}`} />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/reports/:reportId" element={<ReportDetailPage key={location.pathname} />} />
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
