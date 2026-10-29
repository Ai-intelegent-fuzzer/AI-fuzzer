import type {
  ApiAnalysisResult,
  ApiExecutionResult,
  ApiFinding,
  ApiFuzzCase,
  ApiHealth,
  ApiScanRecord,
  ApiScanResult,
  ApiTarget,
} from '../types';

const timeoutMs = 15_000;

export const apiBaseUrl = (import.meta.env?.VITE_API_BASE_URL?.trim() || '').replace(/\/+$/, '');

export class ApiError extends Error {
  readonly status?: number;

  constructor(
    message: string,
    status?: number,
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

type Validator<T> = (value: unknown) => value is T;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasString(value: Record<string, unknown>, key: string): boolean {
  return typeof value[key] === 'string';
}

function hasNullableString(value: Record<string, unknown>, key: string): boolean {
  return value[key] === null || typeof value[key] === 'string';
}

function hasNumber(value: Record<string, unknown>, key: string): boolean {
  return typeof value[key] === 'number' && Number.isFinite(value[key]);
}

function hasNullableNumber(value: Record<string, unknown>, key: string): boolean {
  return value[key] === null || hasNumber(value, key);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function isObjectArray(value: unknown): value is Array<Record<string, unknown>> {
  return Array.isArray(value) && value.every(isRecord);
}

function isHealth(value: unknown): value is ApiHealth {
  return isRecord(value) && hasString(value, 'status');
}

function isTarget(value: unknown): value is ApiTarget {
  return (
    isRecord(value) &&
    hasString(value, 'target_id') &&
    hasString(value, 'name') &&
    ['openai_compatible', 'chatbot', 'rag', 'agent'].includes(String(value.target_type)) &&
    hasString(value, 'endpoint') &&
    hasNullableString(value, 'model') &&
    ['openai', 'groq', 'gemini'].includes(String(value.provider)) &&
    hasNullableString(value, 'description')
  );
}

function isScanMetrics(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasNumber(value, 'total_generated_cases') &&
    hasNumber(value, 'total_executed_cases') &&
    hasNumber(value, 'successful_executions') &&
    hasNumber(value, 'failed_executions') &&
    hasNumber(value, 'timeouts') &&
    hasNumber(value, 'retries') &&
    hasNumber(value, 'mutations_generated') &&
    isStringArray(value.mutation_strategies_used) &&
    isStringArray(value.categories_tested) &&
    hasNumber(value, 'vulnerable_cases') &&
    hasNumber(value, 'findings') &&
    hasNumber(value, 'average_execution_time_ms') &&
    hasNumber(value, 'total_execution_time_ms') &&
    isRecord(value.category_statistics)
  );
}

function isScanCoverage(value: unknown): boolean {
  return (
    isRecord(value) &&
    isStringArray(value.categories_tested) &&
    isStringArray(value.mutation_strategies_tested) &&
    Array.isArray(value.mutation_depths) &&
    value.mutation_depths.every((depth) => typeof depth === 'number') &&
    hasNumber(value, 'unique_prompts') &&
    hasNumber(value, 'unique_test_cases') &&
    hasNumber(value, 'target_responses')
  );
}

function isScan(value: unknown): value is ApiScanRecord {
  return (
    isRecord(value) &&
    hasString(value, 'scan_id') &&
    hasString(value, 'target_id') &&
    hasString(value, 'status') &&
    hasString(value, 'created_at') &&
    hasNullableString(value, 'started_at') &&
    hasNullableString(value, 'completed_at') &&
    hasNumber(value, 'requested_case_count') &&
    hasNumber(value, 'generated_case_count') &&
    hasNumber(value, 'executed_case_count') &&
    hasNumber(value, 'finding_count') &&
    hasNumber(value, 'error_count') &&
    isScanMetrics(value.metrics) &&
    isScanCoverage(value.coverage) &&
    hasNullableString(value, 'failure_reason')
  );
}

function isFuzzCase(value: unknown): value is ApiFuzzCase {
  return (
    isRecord(value) &&
    hasString(value, 'case_id') &&
    hasString(value, 'prompt') &&
    hasString(value, 'category') &&
    hasNullableString(value, 'parent_case_id') &&
    hasNullableString(value, 'mutation_strategy') &&
    hasNumber(value, 'mutation_depth') &&
    hasNullableString(value, 'sequence_id') &&
    isRecord(value.metadata)
  );
}

function isExecution(value: unknown): value is ApiExecutionResult {
  return (
    isRecord(value) &&
    hasString(value, 'target_id') &&
    hasString(value, 'case_id') &&
    hasNullableString(value, 'scan_id') &&
    hasString(value, 'status') &&
    hasNullableNumber(value, 'status_code') &&
    hasNullableNumber(value, 'response_time_ms') &&
    hasNullableString(value, 'response_body') &&
    hasString(value, 'message') &&
    hasNumber(value, 'attempts') &&
    hasNumber(value, 'retries') &&
    hasNullableString(value, 'failure_reason') &&
    typeof value.response_truncated === 'boolean' &&
    hasNullableString(value, 'provider') &&
    hasNullableString(value, 'model') &&
    hasNullableNumber(value, 'prompt_tokens') &&
    hasNullableNumber(value, 'completion_tokens') &&
    hasNullableNumber(value, 'total_tokens')
  );
}

function isFinding(value: unknown): value is ApiFinding {
  return (
    isRecord(value) &&
    hasString(value, 'finding_id') &&
    hasString(value, 'case_id') &&
    hasString(value, 'target_id') &&
    hasNullableString(value, 'scan_id') &&
    hasString(value, 'category') &&
    hasString(value, 'title') &&
    hasNullableString(value, 'description') &&
    hasNullableString(value, 'detection_rationale') &&
    hasString(value, 'severity') &&
    hasString(value, 'confidence') &&
    hasString(value, 'evidence') &&
    hasString(value, 'recommendation') &&
    hasString(value, 'timestamp') &&
    hasNullableString(value, 'attack_id') &&
    hasNullableString(value, 'attack_category') &&
    hasNullableString(value, 'attack_name') &&
    hasNullableString(value, 'expected_behavior') &&
    hasNullableString(value, 'observed_behavior') &&
    hasNullableString(value, 'indicator_type') &&
    isRecord(value.reproducibility) &&
    isRecord(value.metadata)
  );
}

function isAnalysis(value: unknown): value is ApiAnalysisResult {
  return (
    isRecord(value) &&
    hasString(value, 'target_id') &&
    hasString(value, 'case_id') &&
    hasNullableString(value, 'scan_id') &&
    hasString(value, 'category') &&
    typeof value.vulnerable === 'boolean' &&
    hasString(value, 'status') &&
    Array.isArray(value.findings) &&
    value.findings.every(isFinding) &&
    hasNullableString(value, 'attack_id') &&
    hasNullableString(value, 'expected_behavior') &&
    hasNullableString(value, 'observed_behavior') &&
    isObjectArray(value.indicators)
  );
}

function isScanResult(value: unknown): value is ApiScanResult {
  return (
    isRecord(value) &&
    isFuzzCase(value.case) &&
    isExecution(value.execution) &&
    isAnalysis(value.analysis)
  );
}

async function request<T>(
  path: string,
  validator: Validator<T>,
): Promise<T> {
  const controller = new AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort(), timeoutMs);
  const requestPath = apiBaseUrl ? path : `/api${path}`;
  try {
    const response = await fetch(`${apiBaseUrl}${requestPath}`, {
      headers: { Accept: 'application/json' },
      signal: controller.signal,
    });

    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      if (controller.signal.aborted) {
        throw new ApiError(`The backend request timed out after ${timeoutMs / 1000} seconds.`);
      }
      throw new ApiError(
        response.ok
          ? 'The backend returned malformed JSON.'
          : `The backend returned HTTP ${response.status} without a valid JSON error response.`,
        response.status,
      );
    }

    if (!response.ok) {
      const detail =
        isRecord(payload) && typeof payload.detail === 'string' ? payload.detail : undefined;
      throw new ApiError(detail ?? `Backend request failed with HTTP ${response.status}.`, response.status);
    }

    if (!validator(payload)) {
      throw new ApiError('The backend response did not match the expected API schema.', response.status);
    }

    return payload;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (controller.signal.aborted) {
      throw new ApiError(`The backend request timed out after ${timeoutMs / 1000} seconds.`);
    }
    throw new ApiError(
      error instanceof Error
        ? `Could not connect to the backend: ${error.message}`
        : 'Could not connect to the backend.',
    );
  } finally {
    globalThis.clearTimeout(timeout);
  }
}

function isTargetList(value: unknown): value is ApiTarget[] {
  return Array.isArray(value) && value.every(isTarget);
}

function isScanResultList(value: unknown): value is ApiScanResult[] {
  return Array.isArray(value) && value.every(isScanResult);
}

export function getHealth(): Promise<ApiHealth> {
  return request('/health', isHealth);
}

export function getTargets(): Promise<ApiTarget[]> {
  return request('/targets', isTargetList);
}

export function getTarget(targetId: string): Promise<ApiTarget> {
  return request(`/targets/${encodeURIComponent(targetId)}`, isTarget);
}

export function getScan(scanId: string): Promise<ApiScanRecord> {
  return request(`/scans/${encodeURIComponent(scanId)}`, isScan);
}

export function getScanResults(scanId: string): Promise<ApiScanResult[]> {
  return request(`/scans/${encodeURIComponent(scanId)}/results`, isScanResultList);
}
