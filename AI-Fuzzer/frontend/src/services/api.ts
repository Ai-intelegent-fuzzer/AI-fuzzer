import type {
  ApiError,
  ApiFinding,
  ApiReport,
  ApiScan,
  ApiScanResult,
  ApiTarget,
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

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? '/api';

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...options.headers,
    },
  });

  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as ApiError | null;
    const detail = typeof payload?.detail === 'string'
      ? payload.detail
      : payload?.detail?.message ?? `Request failed (${response.status})`;
    throw new Error(detail);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}

const targetTypeMap: Record<ApiTarget['target_type'], Target['type']> = {
  openai_compatible: 'LLM API',
  chatbot: 'AI Chatbot',
  rag: 'RAG Application',
  agent: 'AI Agent',
};

const apiTargetTypeMap: Record<Target['type'], ApiTarget['target_type']> = {
  'LLM API': 'openai_compatible',
  'AI Chatbot': 'chatbot',
  'RAG Application': 'rag',
  'AI Agent': 'agent',
};

const toTarget = (item: ApiTarget): Target => ({
  targetId: item.target_id,
  name: item.name,
  type: targetTypeMap[item.target_type],
  status: item.connection_status === 'reachable'
    ? 'Operational'
    : !item.connection_status || item.connection_status === 'unknown'
      ? 'Unknown'
      : item.connection_status === 'timeout' || item.connection_status === 'error'
        ? 'Offline'
        : 'Warning',
  endpoint: item.endpoint,
  lastTested: item.last_tested ?? '',
  connectionStatus: item.connection_status === 'reachable'
    ? 'Operational'
    : !item.connection_status || item.connection_status === 'unknown'
      ? 'Unknown'
      : item.connection_status === 'timeout' || item.connection_status === 'error'
        ? 'Offline'
        : 'Warning',
  riskProfile: 'Not assessed',
  authType: 'API Key',
  modelName: item.model ?? '',
  description: item.description ?? '',
  provider: item.provider,
  apiPath: item.api_path ?? '',
  authHeader: item.auth_header ?? 'Authorization',
  systemPrompt: item.system_prompt ?? '',
  temperature: item.temperature ?? 0,
  maxOutputTokens: item.max_output_tokens ?? 256,
});

const statusMap: Record<ApiScan['status'], Scan['status']> = {
  created: 'Queued',
  queued: 'Queued',
  running: 'Running',
  paused: 'Queued',
  completed: 'Completed',
  failed: 'Failed',
  cancelled: 'Cancelled',
};

function formatDuration(milliseconds: number): string {
  const seconds = Math.floor(milliseconds / 1000);
  const hours = String(Math.floor(seconds / 3600)).padStart(2, '0');
  const minutes = String(Math.floor((seconds % 3600) / 60)).padStart(2, '0');
  const remainingSeconds = String(seconds % 60).padStart(2, '0');
  return `${hours}:${minutes}:${remainingSeconds}`;
}

const toScan = (item: ApiScan): Scan => {
  const totalMilliseconds = item.status === 'running' && item.started_at
    ? Date.now() - Date.parse(item.started_at)
    : item.metrics?.total_execution_time_ms
      ?? (item.started_at && item.completed_at
        ? Date.parse(item.completed_at) - Date.parse(item.started_at)
        : 0);

  return {
    scanId: item.scan_id,
    target: item.target_id,
    targetId: item.target_id,
    status: statusMap[item.status],
    requestedCases: item.requested_case_count,
    testsTotal: item.generated_case_count || item.requested_case_count,
    testsCompleted: item.executed_case_count,
    findingsCount: item.finding_count,
    startedAt: item.started_at ?? item.created_at,
    endedAt: item.completed_at ?? undefined,
    duration: formatDuration(totalMilliseconds),
    categories: item.executed_categories
      ?? item.coverage?.executed_categories
      ?? item.coverage?.categories_tested
      ?? item.metrics?.categories_tested
      ?? [],
    requestedCategories: item.requested_categories ?? item.coverage?.requested_categories ?? [],
    generatedCategories: item.generated_categories ?? item.coverage?.generated_categories ?? [],
    executedCategories: item.executed_categories ?? item.coverage?.executed_categories ?? [],
    categoryCoveragePercent: item.category_coverage_percent
      ?? item.coverage?.category_coverage_percent
      ?? 0,
    coverageWarning: item.coverage_warning ?? undefined,
    progress: item.generated_case_count
      ? Math.min(100, Math.round((item.executed_case_count / item.generated_case_count) * 100))
      : 0,
    failureReason: item.failure_reason ?? undefined,
  };
};

const severityMap: Record<ApiFinding['severity'], Finding['severity']> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Informational',
};

const confidenceMap: Record<ApiFinding['confidence'], Finding['confidence']> = {
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

const toFinding = (item: ApiFinding, targetName = item.target_id): Finding => ({
  findingId: item.finding_id,
  category: item.category,
  scanId: item.scan_id ?? undefined,
  vulnerabilityType: item.title || item.category.replace(/_/g, ' '),
  severity: severityMap[item.severity],
  confidence: confidenceMap[item.confidence],
  targetId: item.target_id,
  targetName,
  testId: item.case_id,
  evidence: item.evidence,
  expectedBehavior: item.expected_behavior ?? 'Not recorded by the analyzer.',
  actualBehavior: item.observed_behavior ?? 'Not recorded by the analyzer.',
  timestamp: item.timestamp,
  recommendation: item.recommendation,
  detectionResult: item.analysis_status === 'pass'
    ? 'PASS'
    : item.analysis_status === 'inconclusive'
      ? 'INCONCLUSIVE'
      : 'FAIL',
  analysisStatus: item.analysis_status ?? undefined,
  riskScore: item.risk_score,
});

const toReport = (item: ApiReport): Report => ({
  reportId: item.report_id,
  title: item.title,
  generatedAt: item.generated_at,
  format: item.format,
  status: item.status,
  findingsCount: item.findings_count,
  summary: item.summary,
  scanId: item.scan_id,
  targetId: item.target_id,
  targetName: item.target_name,
  highestSeverity: item.highest_severity ? severityMap[item.highest_severity] : undefined,
  executiveSummary: item.executive_summary,
  targetInformation: item.target_information,
  scanConfiguration: item.scan_configuration,
  testsExecuted: item.tests_executed,
  severityDistribution: item.severity_distribution,
  evidenceReferences: item.evidence_references,
  recommendedRemediation: item.recommended_remediation,
  projectName: item.project_name,
  assessmentScope: item.assessment_scope,
  authorizationStatement: item.authorization_statement,
  methodology: item.methodology,
  categoriesExecuted: item.categories_executed,
  categoriesRequested: item.categories_requested,
  categoriesGenerated: item.categories_generated,
  categoryCoveragePercent: item.category_coverage_percent,
  inconclusiveAnalyses: item.inconclusive_analyses,
  findingsBySeverity: item.findings_by_severity,
  coverageWarning: item.coverage_warning ?? undefined,
  conclusion: item.conclusion,
  limitations: item.limitations,
  targetProvider: item.target_provider ?? undefined,
  targetModel: item.target_model ?? undefined,
  requestedCases: item.requested_cases,
  generatedCases: item.generated_cases,
  failedExecutions: item.failed_executions,
  scanStatus: item.scan_status,
  detailedFindings: item.detailed_findings.map((finding) => ({
    id: finding.id,
    type: finding.type,
    severity: severityMap[finding.severity],
    description: finding.description,
    evidence: finding.evidence,
    recommendation: finding.recommendation,
    category: finding.category,
    confidence: finding.confidence,
    riskScore: finding.risk_score,
    provider: finding.provider,
    model: finding.model,
    testCaseId: finding.test_case_id,
    attackId: finding.attack_id,
    expectedBehavior: finding.expected_behavior,
    observedBehavior: finding.observed_behavior,
    reproductionSteps: finding.reproduction_steps,
    impact: finding.impact,
    responseExcerpt: finding.response_excerpt,
  })),
});

function targetPayload(target: TargetDraft) {
  return {
    name: target.name,
    target_type: apiTargetTypeMap[target.type],
    endpoint: target.endpoint,
    model: target.modelName || null,
    provider: target.provider,
    description: target.description || null,
    api_key: target.apiKey || null,
    api_path: target.apiPath || null,
    auth_header: target.authHeader || 'Authorization',
    system_prompt: target.systemPrompt || null,
    temperature: target.temperature ?? 0,
    max_output_tokens: target.maxOutputTokens ?? 256,
  };
}

export const apiClient = {
  async getTargets(): Promise<Target[]> {
    return (await request<ApiTarget[]>('/targets')).map(toTarget);
  },

  async createTarget(target: TargetDraft): Promise<Target> {
    const created = await request<ApiTarget>('/targets', {
      method: 'POST',
      body: JSON.stringify(targetPayload(target)),
    });
    return toTarget(created);
  },

  async updateTarget(targetId: string, target: TargetDraft): Promise<Target> {
    const updated = await request<ApiTarget>(`/targets/${encodeURIComponent(targetId)}`, {
      method: 'PUT',
      body: JSON.stringify(targetPayload(target)),
    });
    return toTarget(updated);
  },

  async deleteTargetCredential(targetId: string): Promise<void> {
    await request<void>(`/targets/${encodeURIComponent(targetId)}/credential`, { method: 'DELETE' });
  },

  async removeTarget(targetId: string): Promise<boolean> {
    await request<void>(`/targets/${encodeURIComponent(targetId)}`, { method: 'DELETE' });
    return true;
  },

  async testTargetConnection(targetId: string, authorizationConfirmed: boolean): Promise<ConnectionTestResult> {
    const result = await request<{
      target_id: string;
      status: 'reachable' | 'unreachable' | 'timeout' | 'error';
      status_code?: number | null;
      response_time_ms?: number | null;
      message: string;
    }>(`/targets/${encodeURIComponent(targetId)}/connectivity`, {
      method: 'POST',
      body: JSON.stringify({ authorization_confirmed: authorizationConfirmed }),
    });
    return {
      status: result.status === 'reachable' ? 'Connection Successful' : 'Connection Failed',
      message: result.message,
    };

  },

  async getScanCategories(): Promise<string[]> {
    return request<string[]>('/scans/categories');
  },

  async getScans(): Promise<Scan[]> {
    const [items, targets] = await Promise.all([
      request<ApiScan[]>('/scans'),
      this.getTargets(),
    ]);
    const targetNames = new Map(targets.map((target) => [target.targetId, target.name]));
    return items.map((item) => ({ ...toScan(item), target: targetNames.get(item.target_id) ?? item.target_id }));
  },

  async getScan(scanId: string): Promise<Scan> {
    const [item, targets] = await Promise.all([
      request<ApiScan>(`/scans/${encodeURIComponent(scanId)}`),
      this.getTargets(),
    ]);
    return {
      ...toScan(item),
      target: targets.find((target) => target.targetId === item.target_id)?.name ?? item.target_id,
    };
  },

  async getScanResults(scanId: string): Promise<ApiScanResult[]> {
    return request<ApiScanResult[]>(`/scans/${encodeURIComponent(scanId)}/results`);
  },

  async getScanFindings(scanId: string): Promise<Finding[]> {
    const [findings, targets] = await Promise.all([
      request<ApiFinding[]>(`/scans/${encodeURIComponent(scanId)}/findings`),
      this.getTargets(),
    ]);
    const targetNames = new Map(targets.map((target) => [target.targetId, target.name]));
    return findings.map((item) => toFinding(item, targetNames.get(item.target_id) ?? item.target_id));
  },

  async startScan(input: ScanStartInput): Promise<Scan> {
    const created = await request<ApiScan>('/scans', {
      method: 'POST',
      body: JSON.stringify({
        target_id: input.targetId,
        authorization_confirmed: input.authorizationConfirmed,
        count: input.count,
        categories: input.categories,
        max_mutation_depth: 0,
        max_mutations_per_case: 0,
        timeout_seconds: input.timeout,
        max_retries: 0,
        concurrency: 1,
        delay_seconds: input.delayMs / 1000,
      }),
    });
    return toScan(created);
  },

  async cancelScan(scanId: string): Promise<Scan> {
    return toScan(await request<ApiScan>(`/scans/${encodeURIComponent(scanId)}/cancel`, { method: 'POST' }));
  },

  async getFindings(filters: { category?: string; severity?: string; status?: string } = {}): Promise<Finding[]> {
    const query = new URLSearchParams();
    if (filters.category) query.set('category', filters.category);
    if (filters.severity) query.set('severity', filters.severity.toLowerCase());
    if (filters.status) query.set('status', filters.status.toLowerCase());
    const [findings, targets] = await Promise.all([
      request<ApiFinding[]>(`/scans/findings${query.size ? `?${query}` : ''}`),
      this.getTargets(),
    ]);
    const targetNames = new Map(targets.map((target) => [target.targetId, target.name]));
    return findings.map((item) => toFinding(item, targetNames.get(item.target_id) ?? item.target_id));
  },

  async getFinding(findingId: string): Promise<Finding> {
    const [item, targets] = await Promise.all([
      request<ApiFinding>(`/scans/findings/${encodeURIComponent(findingId)}`),
      this.getTargets(),
    ]);
    const targetName = targets.find((target) => target.targetId === item.target_id)?.name ?? item.target_id;
    return toFinding(item, targetName);
  },

  async getReports(): Promise<Report[]> {
    return (await request<ApiReport[]>('/reports')).map(toReport);
  },

  async generateReport(scanId: string): Promise<Report> {
    return toReport(await request<ApiReport>(`/reports/${encodeURIComponent(scanId)}/generate`, { method: 'POST' }));
  },

  async getReport(reportId: string): Promise<Report> {
    return toReport(await request<ApiReport>(`/reports/${encodeURIComponent(reportId)}`));
  },

  async getSystemHealth(): Promise<SystemHealthState> {
    const [health, scans] = await Promise.all([
      request<{ status: string }>('/health'),
      request<ApiScan[]>('/scans'),
    ]);
    const ready = health.status === 'healthy';
    return {
      scannerEngine: ready ? 'Backend healthy' : 'Unavailable',
      responseAnalyzer: ready ? 'Not separately probed' : 'Unavailable',
      evidenceStore: 'SQLite (persistent)',
      activeScans: scans.filter((scan) => ['created', 'queued', 'running', 'paused'].includes(scan.status)).length,
    };
  },

  async getDashboardSummary(): Promise<DashboardSummary> {
    const overview = await request<{
      total_scans: number;
      tests_executed: number;
      total_findings: number;
      critical_high_findings: number;
    }>('/scans/analytics/overview');
    return {
      totalScans: overview.total_scans,
      testsExecuted: overview.tests_executed,
      vulnerabilitiesFound: overview.total_findings,
      criticalHighFindings: overview.critical_high_findings,
    };
  },

  async getSeverityDistribution(): Promise<Array<{ name: string; value: number }>> {
    return request('/scans/analytics/severity');
  },

  async getCategoryDistribution(): Promise<Array<{ name: string; value: number }>> {
    return request('/scans/analytics/categories');
  },
};

export default apiClient;
