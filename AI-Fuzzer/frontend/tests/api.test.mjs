import assert from 'node:assert/strict';
import test from 'node:test';
import { getHealth, getScan, getScanResults, getTargets, ApiError } from '../src/services/api.ts';

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function scanRecord(status) {
  return {
    scan_id: 'scan-id',
    target_id: 'target-id',
    status,
    created_at: '2026-10-28T12:00:00Z',
    started_at: null,
    completed_at: null,
    requested_case_count: 1,
    generated_case_count: 0,
    executed_case_count: 0,
    finding_count: 0,
    error_count: 0,
    metrics: {
      total_generated_cases: 0,
      total_executed_cases: 0,
      successful_executions: 0,
      failed_executions: 0,
      timeouts: 0,
      retries: 0,
      mutations_generated: 0,
      mutation_strategies_used: [],
      categories_tested: [],
      vulnerable_cases: 0,
      findings: 0,
      average_execution_time_ms: 0,
      total_execution_time_ms: 0,
      category_statistics: {},
    },
    coverage: {
      categories_tested: [],
      mutation_strategies_tested: [],
      mutation_depths: [],
      unique_prompts: 0,
      unique_test_cases: 0,
      target_responses: 0,
    },
    failure_reason: null,
  };
}

function replaceFetch(t, implementation) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = implementation;
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
}

test('reads health and registered targets from the backend', async (t) => {
  replaceFetch(t, async (url) => {
    if (String(url).endsWith('/health')) return jsonResponse({ status: 'healthy' });
    return jsonResponse([{
      target_id: 'target-id',
      name: 'Local authorized target',
      target_type: 'openai_compatible',
      endpoint: 'https://provider.example/v1/chat/completions',
      model: 'test-model',
      provider: 'groq',
      description: null,
    }]);
  });

  assert.deepEqual(await getHealth(), { status: 'healthy' });
  assert.equal((await getTargets())[0].provider, 'groq');
});

test('surfaces backend HTTP errors and status codes', async (t) => {
  replaceFetch(t, async () => jsonResponse({ detail: 'Target not found' }, 404));

  await assert.rejects(getScan('missing'), (error) => {
    assert.ok(error instanceof ApiError);
    assert.equal(error.status, 404);
    assert.equal(error.message, 'Target not found');
    return true;
  });
});

test('rejects malformed or incomplete backend response shapes', async (t) => {
  replaceFetch(t, async () => jsonResponse([{ target_id: 'incomplete' }]));

  await assert.rejects(getTargets(), /expected API schema/);

  replaceFetch(t, async () => jsonResponse([{ analysis: {} }]));
  await assert.rejects(getScanResults('scan-id'), /expected API schema/);
});

test('accepts terminal scan statuses without inventing progress', async (t) => {
  let currentStatus = 'completed';
  replaceFetch(t, async () => jsonResponse(scanRecord(currentStatus)));

  assert.equal((await getScan('scan-id')).status, 'completed');
  currentStatus = 'failed';
  assert.equal((await getScan('scan-id')).status, 'failed');
  currentStatus = 'cancelled';
  assert.equal((await getScan('scan-id')).status, 'cancelled');
});
