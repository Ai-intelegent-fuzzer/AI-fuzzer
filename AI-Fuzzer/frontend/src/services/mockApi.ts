import {
  dashboardSummary,
  mockFindings,
  mockReports,
  mockScans,
  mockSystemHealth,
  mockTargets,
  severityDistribution,
  vulnerabilityDistribution,
} from '../data/mockData';
import type {
  ConnectionTestResult,
  DashboardSummary,
  Finding,
  Report,
  Scan,
  ScanStartInput,
  SystemHealthState,
  Target,
  TargetDraft,
} from '../types';

const clone = <T,>(value: T): T => JSON.parse(JSON.stringify(value));

const serviceState = {
  targets: clone(mockTargets),
  scans: clone(mockScans),
  findings: clone(mockFindings),
  reports: clone(mockReports),
  health: clone(mockSystemHealth),
};

export interface AppService {
  getTargets(): Promise<Target[]>;
  createTarget(target: TargetDraft): Promise<Target>;
  removeTarget(targetId: string): Promise<boolean>;
  testTargetConnection(input: { name: string; endpoint: string }): Promise<ConnectionTestResult>;
  getScans(): Promise<Scan[]>;
  getScan(scanId: string): Promise<Scan | null>;
  startScan(input: ScanStartInput): Promise<Scan>;
  cancelScan(scanId: string): Promise<Scan | null>;
  getFindings(): Promise<Finding[]>;
  getFinding(findingId: string): Promise<Finding | null>;
  getReports(): Promise<Report[]>;
  getReport(reportId: string): Promise<Report | null>;
  getSystemHealth(): Promise<SystemHealthState>;
  getDashboardSummary(): Promise<DashboardSummary>;
}

export const mockAppService: AppService = {
  async getTargets() {
    return serviceState.targets;
  },

  async createTarget(target) {
    const nextId = `TGT-${String(serviceState.targets.length + 1).padStart(3, '0')}`;
    const created: Target = {
      targetId: nextId,
      name: target.name,
      type: target.type,
      status: 'Operational',
      endpoint: target.endpoint,
      lastTested: new Date().toISOString(),
      riskProfile: 'Low',
      authType: target.authType,
      modelName: target.modelName || '',
      description: target.description || 'Synthetic demo target registered for internal assessment.',
      lastScan: 'Pending',
      createdAt: new Date().toISOString(),
    };

    serviceState.targets = [created, ...serviceState.targets];
    return created;
  },

  async removeTarget(targetId) {
    const previousLength = serviceState.targets.length;
    serviceState.targets = serviceState.targets.filter((item) => item.targetId !== targetId);
    return serviceState.targets.length !== previousLength;
  },

  async testTargetConnection({ name, endpoint }) {
    await new Promise((resolve) => setTimeout(resolve, 650));

    const failed = /fail|blocked|error/i.test(endpoint) || /blocked|fail/i.test(name);

    return failed
      ? {
          status: 'Connection Failed',
          message: 'Connection test failed in the demo environment. Synthetic mock status only.',
        }
      : {
          status: 'Connection Successful',
          message: 'Connection test passed. This is a mock service response and not a live backend check.',
        };
  },

  async getScans() {
    return serviceState.scans;
  },

  async getScan(scanId) {
    return serviceState.scans.find((scan) => scan.scanId === scanId) ?? null;
  },

  async startScan(input) {
    const target = serviceState.targets.find((item) => item.targetId === input.targetId) ?? serviceState.targets[0];
    const scanId = `SCAN-${String(serviceState.scans.length + 42).padStart(4, '0')}`;
    const startedAt = new Date().toISOString();
    const createdScan: Scan = {
      scanId,
      target: target?.name ?? 'Selected target',
      targetId: target?.targetId,
      name: input.name,
      status: 'Running',
      testsTotal: 280,
      testsCompleted: 0,
      findingsCount: 0,
      startedAt,
      duration: '00:00:00',
      categories: input.categories,
      profile: input.profile,
      timeout: input.timeout,
      delayMs: input.delayMs,
      currentStage: 'Preparing Test Cases',
      progress: 0,
      currentCategory: input.categories[0] ?? 'Prompt Injection',
      elapsedSeconds: 0,
    };

    serviceState.scans = [createdScan, ...serviceState.scans];
    return createdScan;
  },

  async cancelScan(scanId) {
    const found = serviceState.scans.find((scan) => scan.scanId === scanId);
    if (!found) return null;

    found.status = 'Cancelled';
    found.currentStage = 'Finalizing Report';
    found.progress = 100;
    found.endedAt = new Date().toISOString();
    found.duration = '00:04:11';

    return found;
  },

  async getFindings() {
    return serviceState.findings;
  },

  async getFinding(findingId) {
    return serviceState.findings.find((finding) => finding.findingId === findingId) ?? null;
  },

  async getReports() {
    return serviceState.reports;
  },

  async getReport(reportId) {
    return serviceState.reports.find((report) => report.reportId === reportId) ?? null;
  },

  async getSystemHealth() {
    return serviceState.health;
  },

  async getDashboardSummary() {
    const totalScans = serviceState.scans.length;
    const testsExecuted = serviceState.scans.reduce((sum, scan) => sum + (scan.testsCompleted || scan.testsTotal), 0);
    const vulnerabilitiesFound = serviceState.findings.length;
    const criticalHighFindings = serviceState.findings.filter(
      (finding) => finding.severity === 'Critical' || finding.severity === 'High',
    ).length;

    return {
      totalScans,
      testsExecuted,
      vulnerabilitiesFound,
      criticalHighFindings,
    };
  },
};

export const demoSeverityDistribution = severityDistribution;
export const demoVulnerabilityDistribution = vulnerabilityDistribution;
export const liveDashboardSummary = dashboardSummary;
