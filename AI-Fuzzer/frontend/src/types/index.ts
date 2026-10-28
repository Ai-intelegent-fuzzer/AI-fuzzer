export interface ApiHealth {
  status: string;
}

export interface ApiTarget {
  target_id: string;
  name: string;
  target_type: 'openai_compatible' | 'chatbot' | 'rag' | 'agent';
  endpoint: string;
  model: string | null;
  provider: 'openai' | 'groq' | 'gemini';
  description: string | null;
}

export type ScanStatus =
  | 'created'
  | 'queued'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | string;

export interface ScanMetrics {
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

export interface ScanCoverage {
  categories_tested: string[];
  mutation_strategies_tested: string[];
  mutation_depths: number[];
  unique_prompts: number;
  unique_test_cases: number;
  target_responses: number;
}

export interface ApiScanRecord {
  scan_id: string;
  target_id: string;
  status: ScanStatus;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  requested_case_count: number;
  generated_case_count: number;
  executed_case_count: number;
  finding_count: number;
  error_count: number;
  metrics: ScanMetrics;
  coverage: ScanCoverage;
  failure_reason: string | null;
}

export interface ApiFuzzCase {
  case_id: string;
  prompt: string;
  category: string;
  parent_case_id: string | null;
  mutation_strategy: string | null;
  mutation_depth: number;
  sequence_id: string | null;
  metadata: Record<string, unknown>;
}

export interface ApiExecutionResult {
  target_id: string;
  case_id: string;
  scan_id: string | null;
  status: string;
  status_code: number | null;
  response_time_ms: number | null;
  response_body: string | null;
  message: string;
  attempts: number;
  retries: number;
  failure_reason: string | null;
  response_truncated: boolean;
  provider: string | null;
  model: string | null;
  prompt_tokens: number | null;
  completion_tokens: number | null;
  total_tokens: number | null;
}

export interface ApiFinding {
  finding_id: string;
  case_id: string;
  target_id: string;
  scan_id: string | null;
  category: string;
  title: string;
  description: string | null;
  detection_rationale: string | null;
  severity: string;
  confidence: string;
  evidence: string;
  recommendation: string;
  timestamp: string;
  attack_id: string | null;
  attack_category: string | null;
  attack_name: string | null;
  expected_behavior: string | null;
  observed_behavior: string | null;
  indicator_type: string | null;
  reproducibility: Record<string, unknown>;
  metadata: Record<string, unknown>;
}

export interface ApiAnalysisResult {
  target_id: string;
  case_id: string;
  scan_id: string | null;
  category: string;
  vulnerable: boolean;
  status: 'pass' | 'fail' | 'inconclusive' | string;
  findings: ApiFinding[];
  attack_id: string | null;
  expected_behavior: string | null;
  observed_behavior: string | null;
  indicators: Array<Record<string, unknown>>;
}

export interface ApiScanResult {
  case: ApiFuzzCase;
  execution: ApiExecutionResult;
  analysis: ApiAnalysisResult;
}
