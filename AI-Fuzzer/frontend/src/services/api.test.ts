import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiClient } from './api';

const targetResponse = {
  target_id: 'authorized-target',
  name: 'Authorized test target',
  target_type: 'chatbot' as const,
  endpoint: 'https://controlled.example.test/chat',
  provider: 'openai' as const,
  model: null,
  description: null,
};

const scanResponse = {
  scan_id: 'scan-123',
  target_id: 'authorized-target',
  status: 'completed' as const,
  created_at: '2026-10-30T12:00:00Z',
  started_at: '2026-10-30T12:00:01Z',
  completed_at: '2026-10-30T12:00:03Z',
  requested_case_count: 2,
  generated_case_count: 2,
  executed_case_count: 2,
  finding_count: 1,
  error_count: 0,
  metrics: {
    total_execution_time_ms: 2500,
    categories_tested: ['prompt_injection'],
  },
  coverage: { categories_tested: ['prompt_injection'] },
};

const jsonResponse = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { 'Content-Type': 'application/json' },
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('apiClient', () => {
  it('maps backend target and scan schemas to frontend models', async () => {
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/targets')) return jsonResponse([targetResponse]);
      if (url.endsWith('/scans')) return jsonResponse([scanResponse]);
      throw new Error(`Unexpected request: ${url}`);
    }));

    const targets = await apiClient.getTargets();
    const scans = await apiClient.getScans();

    expect(targets[0]).toMatchObject({
      targetId: 'authorized-target',
      type: 'AI Chatbot',
      status: 'Unknown',
      riskProfile: 'Not assessed',
    });
    expect(scans[0]).toMatchObject({
      scanId: 'scan-123',
      target: 'Authorized test target',
      status: 'Completed',
      testsTotal: 2,
      testsCompleted: 2,
      findingsCount: 1,
      categories: ['prompt_injection'],
      duration: '00:00:02',
    });
  });

  it('posts the configured scan request to the actual scheduler endpoint', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(scanResponse, 202));
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.startScan({
      targetId: 'authorized-target',
      count: 2,
      categories: ['prompt_injection'],
      timeout: 15,
      delayMs: 200,
      authorizationConfirmed: true,
    });

    expect(fetchMock).toHaveBeenCalledWith('/api/scans', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({
        target_id: 'authorized-target',
        authorization_confirmed: true,
        count: 2,
        categories: ['prompt_injection'],
        max_mutation_depth: 0,
        max_mutations_per_case: 0,
        timeout_seconds: 15,
        max_retries: 0,
        concurrency: 1,
        delay_seconds: 0.2,
      }),
    }));
  });

  it('sends provider configuration to the backend target route', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(targetResponse, 201));
    vi.stubGlobal('fetch', fetchMock);

    await apiClient.createTarget({
      name: 'Controlled provider',
      type: 'LLM API',
      provider: 'anthropic',
      endpoint: 'https://api.anthropic.com',
      authType: 'API Key',
      modelName: 'controlled-model',
      description: '',
      apiKey: 'controlled-secret',
      apiPath: '/v1/messages',
      systemPrompt: 'controlled system prompt',
      temperature: 0.3,
      maxOutputTokens: 512,
    });

    expect(fetchMock).toHaveBeenCalledWith('/api/targets', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({
        name: 'Controlled provider',
        target_type: 'openai_compatible',
        endpoint: 'https://api.anthropic.com',
        model: 'controlled-model',
        provider: 'anthropic',
        description: null,
        api_key: 'controlled-secret',
        api_path: '/v1/messages',
        auth_header: 'Authorization',
        system_prompt: 'controlled system prompt',
        temperature: 0.3,
        max_output_tokens: 512,
      }),
    }));
  });

  it('uses the actual connectivity route and maps its result', async () => {
    const fetchMock = vi.fn(async () => jsonResponse({
      target_id: 'authorized-target',
      status: 'reachable',
      response_time_ms: 4.2,
      message: 'Target endpoint is reachable.',
    }));
    vi.stubGlobal('fetch', fetchMock);

    const result = await apiClient.testTargetConnection('authorized-target', true);

    expect(fetchMock).toHaveBeenCalledWith('/api/targets/authorized-target/connectivity', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ authorization_confirmed: true }),
    }));
    expect(result).toEqual({ status: 'Connection Successful', message: 'Target endpoint is reachable.' });
  });

  it('updates capability profiles and queries categories for a selected target', async () => {
    const profile = {
      capabilities: {
        model_endpoint: {
          enabled: true,
          validation_status: 'configured' as const,
          supported_security_tests: ['prompt_injection'],
          known_limitations: [],
        },
      },
    };
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/targets/authorized-target/capabilities')) {
        expect(init?.method).toBe('PUT');
        expect(init?.body).toBe(JSON.stringify(profile));
        return jsonResponse({
          ...targetResponse,
          target_scope: 'model_endpoint',
          capability_profile: profile,
        });
      }
      if (url.endsWith('/attacks/categories?target_id=authorized-target')) {
        return jsonResponse([{
          category: 'prompt_injection',
          attack_count: 2,
          required_capabilities: [],
          applicable_target_scopes: ['model_endpoint'],
          risk_levels: ['medium'],
          applicable: true,
        }]);
      }
      throw new Error(`Unexpected request: ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    const updated = await apiClient.updateTargetCapabilities('authorized-target', profile);
    const categories = await apiClient.getAttackCategories('authorized-target');

    expect(updated).toMatchObject({
      targetId: 'authorized-target',
      targetScope: 'model_endpoint',
      capabilityProfile: profile,
    });
    expect(categories[0]).toMatchObject({
      category: 'prompt_injection',
      applicable: true,
    });
  });

  it('uses controlled synthetic security test routes and identity context', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/authorization/tests')) {
        expect(init?.body).toBe(JSON.stringify({ scenario: 'horizontal_privilege_escalation' }));
        return jsonResponse({ outcome: 'no_issue_observed', reason: 'Policy denied access.' }, 201);
      }
      if (url.endsWith('/rag/scenarios')) {
        expect(init?.body).toBe(JSON.stringify({ scenario: 'cross_tenant_document_access' }));
        return jsonResponse({ outcome: 'no_issue_observed', documents: [], audits: [] }, 201);
      }
      if (url.endsWith('/tools/security-tests')) {
        expect(init?.body).toBe(JSON.stringify({
          scenario: 'unauthorized_tool_invocation',
          identity_id: 'synthetic-user-a',
          session_id: 'synthetic-session-user-a',
        }));
        return jsonResponse({ outcome: 'no_issue_observed', reason: 'Policy denied access.' }, 201);
      }
      if (url.endsWith('/integrations/security-tests')) {
        expect(init?.body).toBe(JSON.stringify({
          scenario: 'cross_tenant_connector_exposure',
          identity_id: 'synthetic-user-a',
          session_id: 'synthetic-session-user-a',
        }));
        return jsonResponse({ outcome: 'no_issue_observed', reason: 'Policy denied access.' }, 201);
      }
      throw new Error(`Unexpected request: ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);
    const identity = {
      identity_id: 'synthetic-user-a',
      session_id: 'synthetic-session-user-a',
    };

    await apiClient.runAuthorizationScenario('horizontal_privilege_escalation');
    await apiClient.runRagScenario('cross_tenant_document_access');
    await apiClient.runToolSecurityTest('unauthorized_tool_invocation', identity);
    await apiClient.runIntegrationSecurityTest('cross_tenant_connector_exposure', identity);

    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it('maps actual analyzer findings and generated report data', async () => {
    const finding = {
      finding_id: 'finding-1',
      case_id: 'case-1',
      target_id: 'authorized-target',
      scan_id: 'scan-123',
      category: 'prompt_injection',
      title: 'Synthetic boundary finding',
      severity: 'high',
      confidence: 'high',
      evidence: 'Observed synthetic evidence.',
      recommendation: 'Maintain the trust boundary.',
      timestamp: '2026-10-30T12:00:00Z',
      expected_behavior: 'Reject untrusted instruction.',
      observed_behavior: 'Synthetic response.',
      analysis_status: 'fail',
    };
    const report = {
      report_id: 'scan-123',
      title: 'Security assessment',
      generated_at: '2026-10-30T12:00:03Z',
      format: 'JSON',
      status: 'Ready',
      findings_count: 1,
      summary: '1 finding across 3 executed tests.',
      scan_id: 'scan-123',
      target_id: 'authorized-target',
      target_name: 'Authorized test target',
      highest_severity: 'high',
      executive_summary: '1 finding across 3 executed tests.',
      target_information: 'Target ID: authorized-target',
      scan_configuration: 'Requested cases: 2',
      tests_executed: 3,
      severity_distribution: [{ name: 'High', value: 1 }],
      detailed_findings: [{
        id: 'finding-1',
        type: 'Synthetic boundary finding',
        severity: 'high',
        description: 'Observed test result.',
        evidence: 'Observed synthetic evidence.',
        recommendation: 'Maintain the trust boundary.',
      }],
      evidence_references: ['finding-1'],
      recommended_remediation: ['Maintain the trust boundary.'],
    };
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/scans/findings')) return jsonResponse([finding]);
      if (url.endsWith('/targets')) return jsonResponse([targetResponse]);
      if (url.endsWith('/reports/scan-123')) return jsonResponse(report);
      throw new Error(`Unexpected request: ${url}`);
    }));

    const findings = await apiClient.getFindings({ severity: 'high', status: 'fail' });
    const mappedReport = await apiClient.getReport('scan-123');

    expect(findings[0]).toMatchObject({
      findingId: 'finding-1',
      category: 'prompt_injection',
      scanId: 'scan-123',
      targetName: 'Authorized test target',
      severity: 'High',
      analysisStatus: 'fail',
    });
    expect(mappedReport).toMatchObject({
      reportId: 'scan-123',
      findingsCount: 1,
      testsExecuted: 3,
      detailedFindings: [{ id: 'finding-1', severity: 'High' }],
    });
  });
});
