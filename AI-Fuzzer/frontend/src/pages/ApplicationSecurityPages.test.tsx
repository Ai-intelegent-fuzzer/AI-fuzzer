import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiClient } from '../services/api';
import type { Target } from '../types';
import { CapabilitiesPage } from './CapabilitiesPage';
import { SecurityLabPage } from './SecurityLabPage';

const target: Target = {
  targetId: 'synthetic-target',
  name: 'Synthetic application',
  type: 'RAG Application',
  status: 'Unknown',
  endpoint: 'https://controlled.example.test',
  lastTested: '',
  riskProfile: 'Not assessed',
  targetScope: 'ai_application',
  capabilityProfile: {
    capabilities: {
      rag_enabled: {
        enabled: false,
        validation_status: 'not_configured',
        supported_security_tests: [],
        known_limitations: ['Not configured.'],
      },
    },
  },
};

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('application security pages', () => {
  it('displays synthetic fixture metadata and runs controlled local scenarios', async () => {
    const user = userEvent.setup();
    vi.spyOn(apiClient, 'getTargets').mockResolvedValue([target]);
    vi.spyOn(apiClient, 'getSyntheticIdentities').mockResolvedValue([{
      identity_id: 'synthetic-user-a',
      display_name: 'User A',
      tenant_id: 'tenant-a',
      roles: ['user'],
      permissions: ['resource:read:owned'],
      authentication_status: 'authenticated',
      session_id: 'synthetic-session-user-a',
    }]);
    vi.spyOn(apiClient, 'getSyntheticResources').mockResolvedValue([{
      resource_id: 'synthetic-resource-a',
      display_name: 'Synthetic private resource',
      owner_identity_id: 'synthetic-user-a',
      tenant_id: 'tenant-a',
      classification: 'private',
      required_permissions: ['resource:read:owned'],
    }]);
    vi.spyOn(apiClient, 'getRagDocuments').mockResolvedValue([{
      document_id: 'synthetic-rag-document-a',
      title: 'Synthetic support guide',
      owner_identity_id: 'synthetic-user-a',
      tenant_id: 'tenant-a',
      classification: 'private',
      required_permissions: ['resource:read:owned'],
      metadata: {},
      contains_untrusted_instructions: true,
    }]);
    vi.spyOn(apiClient, 'getSyntheticTools').mockResolvedValue([]);
    vi.spyOn(apiClient, 'getMcpServers').mockResolvedValue([]);
    vi.spyOn(apiClient, 'getMcpResources').mockResolvedValue([]);
    vi.spyOn(apiClient, 'getSyntheticIntegrations').mockResolvedValue([]);
    vi.spyOn(apiClient, 'getVectorCollections').mockResolvedValue([{
      collection_id: 'synthetic-vector-collection-default',
      display_name: 'Synthetic Default Collection',
      tenant_id: 'tenant-a',
      created_at: '2025-01-01T00:00:00Z',
    }]);
    vi.spyOn(apiClient, 'getWebSecurityFixtures').mockResolvedValue([{
      fixture_id: 'synthetic-webapp-secure',
      display_name: 'Synthetic Secure Web Application',
      description: 'In-process fixture.',
      simulated: true,
    }]);
    vi.spyOn(apiClient, 'getWebSecurityTests').mockResolvedValue([{
      test_id: 'authorization_control',
      category: 'authorization',
      description: 'Test fixture authorization.',
      expected_behavior: 'Deny unauthorized access.',
      recommendation: 'Enforce authorization.',
    }]);
    vi.spyOn(apiClient, 'getAttackCategories').mockResolvedValue([{
      category: 'rag_security',
      attack_count: 10,
      required_capabilities: ['rag_enabled'],
      applicable_target_scopes: ['ai_application'],
      applicable: true,
    }]);
    const runRag = vi.spyOn(apiClient, 'runRagScenario').mockResolvedValue({
      outcome: 'no_issue_observed',
    });
    const runWeb = vi.spyOn(apiClient, 'runWebSecurityTests').mockResolvedValue({
      fixture_id: 'synthetic-webapp-secure',
      simulated: true,
      results: [{
        evidence_id: 'synthetic-web-evidence-1',
        test_id: 'authorization_control',
        fixture_id: 'synthetic-webapp-secure',
        category: 'authorization',
        status: 'PASS',
        severity: 'low',
        confidence: 'high',
        expected_behavior: 'Deny unauthorized access.',
        observed_behavior: 'The fixture denied the request.',
        recommendation: 'Enforce authorization.',
        evidence_reference: 'synthetic-web-evidence-ref',
      }],
    });

    render(<SecurityLabPage />);

    expect(await screen.findByText('Synthetic support guide')).toBeTruthy();
    expect(screen.getByText('Synthetic private resource')).toBeTruthy();
    expect(screen.queryByText(/private fixture contents/i)).toBeNull();
    const ragScenario = screen.getByLabelText('RAG security scenario').closest<HTMLElement>('.lab-scenario');
    if (!ragScenario) throw new Error('RAG scenario control was not rendered.');
    await user.click(within(ragScenario).getByRole('button', { name: /run synthetic test/i }));
    expect(runRag).toHaveBeenCalledWith('unauthorized_document_retrieval');
    expect(await screen.findByText('no issue observed')).toBeTruthy();

    await user.click(screen.getByRole('button', { name: /run local control simulation/i }));
    expect(runWeb).toHaveBeenCalledWith('synthetic-webapp-secure', ['authorization_control']);
    expect(await screen.findByText(/pass: authorization/i)).toBeTruthy();
  });

  it('edits and persists a target capability profile', async () => {
    const user = userEvent.setup();
    vi.spyOn(apiClient, 'getTargets').mockResolvedValue([target]);
    const update = vi.spyOn(apiClient, 'updateTargetCapabilities').mockImplementation(
      async (_targetId, profile) => ({ ...target, capabilityProfile: profile }),
    );

    render(<CapabilitiesPage />);

    const capabilityHeading = await screen.findByRole('heading', { name: 'rag enabled' });
    const capabilityRow = capabilityHeading.closest<HTMLElement>('.capability-row');
    if (!capabilityRow) throw new Error('Capability control was not rendered.');
    await user.click(within(capabilityRow).getByRole('checkbox', { name: 'Enabled' }));
    await user.click(screen.getByRole('button', { name: /save profile/i }));

    expect(update).toHaveBeenCalledWith('synthetic-target', expect.objectContaining({
      capabilities: expect.objectContaining({
        rag_enabled: expect.objectContaining({
          enabled: true,
          validation_status: 'configured',
        }),
      }),
    }));
    expect((await screen.findByRole('status')).textContent).toContain('Capability profile saved.');
  });
});
