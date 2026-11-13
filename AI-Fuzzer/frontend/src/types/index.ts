export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
export type Confidence = 'High' | 'Medium' | 'Low';
export type DetectionResult = 'PASS' | 'FAIL' | 'INCONCLUSIVE';
export type AnalysisOutcome =
  | 'vulnerability_detected'
  | 'refused_or_blocked'
  | 'no_issue_observed'
  | 'inconclusive'
  | 'execution_failed';
export type FindingVerificationStatus =
  | 'confirmed'
  | 'likely'
  | 'potential'
  | 'inconclusive'
  | 'not_applicable'
  | 'no_issue_observed'
  | 'execution_failure';
export type TargetScope = 'model_endpoint' | 'ai_application' | 'application_integration' | 'simulated';
export type CapabilityName =
  | 'model_endpoint'
  | 'web_application'
  | 'rag_enabled'
  | 'vector_database'
  | 'tool_calling'
  | 'mcp_enabled'
  | 'authentication_enabled'
  | 'authorization_enabled'
  | 'multi_tenant'
  | 'agent_memory'
  | 'external_integrations';
export type CapabilityValidationStatus = 'not_configured' | 'unverified' | 'configured' | 'verified' | 'invalid';
export type ScanStatus = 'Completed' | 'Running' | 'Failed' | 'Queued' | 'Cancelled';
export type TargetType = 'LLM API' | 'AI Chatbot' | 'RAG Application' | 'AI Agent';
export type TargetStatus = 'Operational' | 'Warning' | 'Offline' | 'Unknown';
export type AuthenticationType = 'None' | 'API Key' | 'Bearer Token';
export type ScanProfile = 'Quick' | 'Standard' | 'Comprehensive';
export type VulnerabilityCategory = 'Prompt Injection' | 'Jailbreak' | 'Context Poisoning' | 'Data Leakage';
export type AIProvider = 'openai' | 'groq' | 'gemini' | 'anthropic' | 'mistral' | 'ollama' | 'custom';

export type ApiError = {
  detail?: string | { message?: string };
};

export interface ApiTarget {
  target_id: string;
  name: string;
  target_type: 'openai_compatible' | 'chatbot' | 'rag' | 'agent';
  endpoint: string;
  model?: string | null;
  provider: AIProvider;
  api_path?: string | null;
  auth_header?: string;
  system_prompt?: string | null;
  temperature?: number;
  max_output_tokens?: number;
  connection_status?: 'unknown' | 'reachable' | 'unreachable' | 'timeout' | 'error';
  last_tested?: string | null;
  description?: string | null;
  target_scope?: TargetScope;
  capability_profile?: ApiCapabilityProfile;
}

export interface ApiCapabilitySetting {
  enabled: boolean;
  configuration_reference?: string | null;
  validation_status: CapabilityValidationStatus;
  supported_security_tests: string[];
  known_limitations: string[];
}

export interface ApiCapabilityProfile {
  capabilities: Partial<Record<CapabilityName, ApiCapabilitySetting>>;
}

export interface ApiScan {
  scan_id: string;
  target_id: string;
  retry_of_scan_id?: string | null;
  target_scope?: TargetScope | null;
  capability_profile?: ApiCapabilityProfile | null;
  status: 'created' | 'queued' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled';
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  requested_case_count: number;
  generated_case_count: number;
  executed_case_count: number;
  finding_count: number;
  error_count: number;
  failure_reason?: string | null;
  requested_categories?: string[];
  generated_categories?: string[];
  executed_categories?: string[];
  applicable_categories?: string[];
  not_applicable_categories?: string[];
  skipped_case_count?: number;
  inconclusive_analysis_count?: number;
  category_coverage_percent?: number;
  coverage_warning?: string | null;
  metrics?: ApiScanMetrics;
  coverage?: ApiScanCoverage;
}

export interface ApiScanMetrics {
  total_generated_cases: number;
  total_executed_cases: number;
  successful_executions: number;
  failed_executions: number;
  timeouts: number;
  retries: number;
  mutations_generated: number;
  mutation_strategies_used: string[];
  categories_tested: string[];
  vulnerable_cases: number;
  findings: number;
  average_execution_time_ms: number;
  total_execution_time_ms: number;
  category_statistics: Record<string, Record<string, number>>;
}

export interface ApiScanCoverage {
  requested_categories?: string[];
  generated_categories?: string[];
  executed_categories?: string[];
  applicable_categories?: string[];
  not_applicable_categories?: string[];
  category_coverage_percent?: number;
  categories_tested: string[];
  mutation_strategies_tested: string[];
  mutation_depths: number[];
  unique_prompts: number;
  unique_test_cases: number;
  target_responses: number;
}

export interface ApiScanResult {
  case: {
    case_id: string;
    prompt: string;
    category: string;
    parent_case_id?: string | null;
    mutation_strategy?: string | null;
    mutation_depth: number;
  };
  execution: {
    target_id: string;
    case_id: string;
    scan_id?: string | null;
    status: string;
    status_code?: number | null;
    response_time_ms?: number | null;
    response_body?: string | null;
    message: string;
    attempts: number;
    retries: number;
    failure_reason?: string | null;
    response_truncated: boolean;
    provider?: string | null;
    model?: string | null;
    prompt_tokens?: number | null;
    completion_tokens?: number | null;
    total_tokens?: number | null;
  };
  analysis: {
    target_id: string;
    case_id: string;
    scan_id?: string | null;
    category: string;
    vulnerable: boolean;
    status: 'pass' | 'fail' | 'inconclusive';
    outcome?: AnalysisOutcome;
    findings: ApiFinding[];
    expected_behavior?: string | null;
    observed_behavior?: string | null;
    evidence_provenance?: ApiEvidenceProvenance[];
  };
}

export interface ApiFinding {
  finding_id: string;
  case_id: string;
  target_id: string;
  scan_id?: string | null;
  category: string;
  title: string;
  description?: string | null;
  detection_rationale?: string | null;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  confidence: 'high' | 'medium' | 'low';
  evidence: string;
  recommendation: string;
  timestamp: string;
  expected_behavior?: string | null;
  observed_behavior?: string | null;
  indicator_type?: string | null;
  analysis_status?: 'pass' | 'fail' | 'inconclusive' | null;
  risk_score?: number;
  verification_status?: FindingVerificationStatus;
  evidence_provenance?: ApiEvidenceProvenance[];
  reproduction_reference?: string | null;
}

export interface ApiEvidenceProvenance {
  provenance_id: string;
  scan_id?: string | null;
  test_case_id: string;
  target_id: string;
  canary_identifier?: string | null;
  canary_present_in_protected_context: boolean;
  canary_present_in_test_input: boolean;
  canary_present_in_response: boolean;
  protected_context_verified: boolean;
  disclosure_verified: boolean;
  verification_level: string;
  evidence_type: string;
  analyzer_rule_id?: string | null;
  analyzer_rule_version?: string | null;
  identity_id?: string | null;
  tenant_id?: string | null;
  retrieval_reference?: string | null;
  tool_reference?: string | null;
  timestamp: string;
}

export interface ApiSyntheticIdentity {
  identity_id: string;
  display_name: string;
  tenant_id: string;
  roles: string[];
  permissions: string[];
  authentication_status: string;
  session_id: string;
}

export interface ApiSyntheticResource {
  resource_id: string;
  display_name: string;
  owner_identity_id: string;
  tenant_id: string;
  classification: string;
  required_permissions: string[];
}

export interface ApiRagDocument {
  document_id: string;
  title: string;
  owner_identity_id: string;
  tenant_id: string;
  classification: string;
  required_permissions: string[];
  metadata: Record<string, string>;
  contains_untrusted_instructions: boolean;
}

export interface ApiToolDefinition {
  tool_id: string;
  name: string;
  operation: string;
  risk_classification: string;
  read_only: boolean;
  simulated_state_changing: boolean;
}

export interface ApiMcpServer {
  server_id: string;
  display_name: string;
  trust_level: string;
  simulated: boolean;
  active: boolean;
}

export interface ApiMcpResource {
  resource_id: string;
  server_id: string;
  display_name: string;
  owner_identity_id: string;
  tenant_id: string;
  classification: string;
}

export interface ApiSyntheticIntegration {
  integration_id: string;
  provider_type: string;
  display_name: string;
  tenant_scope: string;
  owner_identity_id: string;
  data_classification: string;
  read_enabled: boolean;
  write_enabled: boolean;
  simulated_execution_mode: 'local_synthetic';
}

export interface ApiVectorCollection {
  collection_id: string;
  display_name: string;
  tenant_id: string;
  created_at: string;
}

export interface ApiVectorSearchResult {
  document: {
    document_id: string;
    collection_id: string;
    title: string;
    content: string;
    owner_identity_id: string;
    tenant_id: string;
    classification: string;
    required_permissions: string[];
    metadata: Record<string, string>;
  };
  similarity: number;
}

export interface ApiMemoryRecord {
  memory_id: string;
  owner_identity_id: string;
  tenant_id: string;
  session_id?: string | null;
  scope: 'user' | 'session' | 'tenant';
  classification: string;
  required_permissions: string[];
  content: string;
  provenance: string;
  created_at: string;
  expires_at?: string | null;
}

export interface ApiWebFixture {
  fixture_id: string;
  display_name: string;
  description: string;
  simulated: boolean;
}

export interface ApiWebTestCase {
  test_id: string;
  category: string;
  description: string;
  expected_behavior: string;
  recommendation: string;
}

export interface ApiWebTestEvidence {
  evidence_id: string;
  test_id: string;
  fixture_id: string;
  category: string;
  status: string;
  severity: string;
  confidence: string;
  expected_behavior: string;
  observed_behavior: string;
  recommendation: string;
  evidence_reference: string;
}

export interface ApiWebTestRun {
  fixture_id: string;
  simulated: boolean;
  results: ApiWebTestEvidence[];
}

export interface ApiAttackCategory {
  category: string;
  attack_count: number;
  required_capabilities: string[];
  applicable_target_scopes: TargetScope[];
  applicable: boolean;
}

export interface ApiBenchmark {
  benchmark_id: string;
  name: string;
  case_count: number;
  categories: string[];
}

export interface ApiScenarioResult {
  scenario?: string;
  outcome?: string;
  expected_authorization?: string;
  actual_authorization?: string;
  expected_authorization_result?: string;
  actual_authorization_result?: string;
  executed?: boolean;
  reason?: string;
  test_id?: string;
  audit_id?: string;
}

export interface Target {
  targetId: string;
  name: string;
  type: TargetType;
  status: TargetStatus;
  endpoint: string;
  lastTested: string;
  riskProfile: 'Low' | 'Medium' | 'High' | 'Not assessed';
  authType?: AuthenticationType;
  modelName?: string;
  description?: string;
  provider?: AIProvider;
  connectionStatus?: TargetStatus;
  apiPath?: string;
  authHeader?: string;
  systemPrompt?: string;
  temperature?: number;
  maxOutputTokens?: number;
  lastScan?: string;
  createdAt?: string;
  targetScope?: TargetScope;
  capabilityProfile?: ApiCapabilityProfile;
}

export interface EvidenceStep {
  label: string;
  value: string;
}

export interface Scan {
  scanId: string;
  target: string;
  targetId?: string;
  retryOfScanId?: string;
  targetScope?: TargetScope;
  capabilityProfile?: ApiCapabilityProfile;
  name?: string;
  status: ScanStatus;
  requestedCases?: number;
  testsTotal: number;
  testsCompleted: number;
  findingsCount: number;
  startedAt: string;
  duration: string;
  endedAt?: string;
  categories?: string[];
  requestedCategories?: string[];
  generatedCategories?: string[];
  executedCategories?: string[];
  applicableCategories?: string[];
  notApplicableCategories?: string[];
  skippedCaseCount?: number;
  inconclusiveAnalysisCount?: number;
  categoryCoveragePercent?: number;
  coverageWarning?: string;
  profile?: ScanProfile;
  timeout?: number;
  delayMs?: number;
  currentStage?: string;
  progress?: number;
  currentCategory?: string;
  elapsedSeconds?: number;
  failureReason?: string;
}

export interface Finding {
  findingId: string;
  category?: string;
  scanId?: string;
  vulnerabilityType: string;
  severity: Severity;
  confidence: Confidence;
  targetId: string;
  targetName: string;
  testId: string;
  evidence: string;
  expectedBehavior: string;
  actualBehavior: string;
  timestamp: string;
  recommendation: string;
  detectionResult: DetectionResult;
  analysisStatus?: 'pass' | 'fail' | 'inconclusive';
  riskScore?: number;
  status?: 'Open' | 'Investigating' | 'Resolved';
  verificationStatus?: FindingVerificationStatus;
  evidenceProvenance?: ApiEvidenceProvenance[];
  evidenceSequence?: EvidenceStep[];
}

export interface Report {
  reportId: string;
  title: string;
  generatedAt: string;
  format: 'JSON' | 'PDF';
  status: 'Ready' | 'Generating' | 'Archived';
  findingsCount: number;
  summary: string;
  scanId?: string;
  targetId?: string;
  targetName?: string;
  highestSeverity?: Severity;
  executiveSummary?: string;
  targetInformation?: string;
  scanConfiguration?: string;
  testsExecuted?: number;
  severityDistribution?: Array<{ name: string; value: number }>;
  detailedFindings?: Array<{
    id: string;
    type: string;
    severity: Severity;
    description: string;
    evidence: string;
    recommendation: string;
    category?: string;
    confidence?: string;
    riskScore?: number;
    provider?: string | null;
    model?: string | null;
    testCaseId?: string | null;
    attackId?: string | null;
    expectedBehavior?: string | null;
    observedBehavior?: string | null;
    reproductionSteps?: string[];
    impact?: string;
    responseExcerpt?: string | null;
    verificationStatus?: FindingVerificationStatus;
    evidenceProvenance?: ApiEvidenceProvenance[];
    reproductionReference?: string | null;
  }>;
  evidenceReferences?: string[];
  recommendedRemediation?: string[];
  projectName?: string;
  assessmentScope?: string;
  authorizationStatement?: string;
  methodology?: string;
  categoriesExecuted?: string[];
  categoriesRequested?: string[];
  categoriesGenerated?: string[];
  categoryCoveragePercent?: number;
  inconclusiveAnalyses?: number;
  findingsBySeverity?: Record<string, number>;
  coverageWarning?: string;
  conclusion?: string;
  limitations?: string[];
  targetProvider?: string;
  targetModel?: string;
  requestedCases?: number;
  generatedCases?: number;
  failedExecutions?: number;
  scanStatus?: string;
  targetScope?: TargetScope;
  capabilityProfile?: ApiCapabilityProfile;
  categoriesApplicable?: string[];
  categoriesNotApplicable?: string[];
  evidenceProvenanceReferences?: string[];
  findingsByVerificationStatus?: Partial<Record<FindingVerificationStatus, number>>;
}

export interface ApiReport {
  report_id: string;
  title: string;
  generated_at: string;
  format: 'JSON';
  status: 'Ready';
  findings_count: number;
  summary: string;
  scan_id: string;
  target_id: string;
  target_name: string;
  highest_severity: ApiFinding['severity'] | null;
  executive_summary: string;
  target_information: string;
  scan_configuration: string;
  tests_executed: number;
  severity_distribution: Array<{ name: string; value: number }>;
  evidence_references: string[];
  recommended_remediation: string[];
  project_name?: string;
  assessment_scope?: string;
  authorization_statement?: string;
  methodology?: string;
  categories_executed?: string[];
  categories_requested?: string[];
  categories_generated?: string[];
  category_coverage_percent?: number;
  inconclusive_analyses?: number;
  findings_by_severity?: Record<string, number>;
  coverage_warning?: string | null;
  conclusion?: string;
  limitations?: string[];
  target_provider?: string | null;
  target_model?: string | null;
  requested_cases?: number;
  generated_cases?: number;
  failed_executions?: number;
  scan_status?: string;
  target_scope?: TargetScope | null;
  capability_profile?: ApiCapabilityProfile | null;
  categories_applicable?: string[];
  categories_not_applicable?: string[];
  evidence_provenance_references?: string[];
  findings_by_verification_status?: Partial<Record<FindingVerificationStatus, number>>;
  detailed_findings: Array<{
    id: string;
    type: string;
    severity: ApiFinding['severity'];
    description: string;
    evidence: string;
    recommendation: string;
    category?: string;
    confidence?: string;
    risk_score?: number;
    provider?: string | null;
    model?: string | null;
    test_case_id?: string | null;
    attack_id?: string | null;
    expected_behavior?: string | null;
    observed_behavior?: string | null;
    reproduction_steps?: string[];
    impact?: string;
    response_excerpt?: string | null;
    verification_status?: FindingVerificationStatus;
    evidence_provenance?: ApiEvidenceProvenance[];
    reproduction_reference?: string | null;
  }>;
}

export interface SystemHealthState {
  scannerEngine: string;
  responseAnalyzer: string;
  evidenceStore: string;
  activeScans: number;
}

export interface DashboardSummary {
  totalScans: number;
  testsExecuted: number;
  vulnerabilitiesFound: number;
  criticalHighFindings: number;
}

export interface TargetDraft {
  name: string;
  type: TargetType;
  provider: AIProvider;
  endpoint: string;
  authType: AuthenticationType;
  modelName: string;
  description: string;
  apiKey?: string;
  apiPath?: string;
  authHeader?: string;
  systemPrompt?: string;
  temperature?: number;
  maxOutputTokens?: number;
}

export interface ConnectionTestResult {
  status: 'Testing...' | 'Connection Successful' | 'Connection Failed';
  message: string;
}

export interface ScanStartInput {
  targetId: string;
  count: number;
  categories: string[];
  timeout: number;
  delayMs: number;
  authorizationConfirmed: boolean;
  benchmarkId?: string;
}
