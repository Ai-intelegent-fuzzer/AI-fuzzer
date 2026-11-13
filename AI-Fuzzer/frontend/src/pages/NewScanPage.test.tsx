import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { apiClient } from '../services/api';
import { NewScanPage } from './NewScanPage';

const target = {
  targetId: 'authorized-target',
  name: 'Authorized test target',
  type: 'AI Chatbot' as const,
  status: 'Unknown' as const,
  endpoint: 'https://controlled.example.test/chat',
  lastTested: '',
  riskProfile: 'Not assessed' as const,
};

const createdScan = {
  scanId: 'scan-returned-by-backend',
  target: target.name,
  targetId: target.targetId,
  status: 'Queued' as const,
  testsTotal: 2,
  testsCompleted: 0,
  findingsCount: 0,
  startedAt: '2026-10-30T12:00:00Z',
  duration: '00:00:00',
};

function CurrentPath() {
  const location = useLocation();
  return <div data-testid="current-path">{location.pathname}</div>;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('NewScanPage workflow', () => {
  it('requires a connectivity check and authorization, then navigates using the returned scan ID', async () => {
    const user = userEvent.setup();
    vi.spyOn(apiClient, 'getTargets').mockResolvedValue([target]);
    vi.spyOn(apiClient, 'getAttackCategories').mockResolvedValue([
      {
        category: 'prompt_injection',
        attack_count: 2,
        required_capabilities: [],
        applicable_target_scopes: ['ai_application'],
        applicable: true,
      },
      {
        category: 'jailbreak',
        attack_count: 2,
        required_capabilities: [],
        applicable_target_scopes: ['ai_application'],
        applicable: true,
      },
    ]);
    vi.spyOn(apiClient, 'testTargetConnection').mockResolvedValue({
      status: 'Connection Successful',
      message: 'Controlled target is reachable.',
    });
    const startScan = vi.spyOn(apiClient, 'startScan').mockResolvedValue(createdScan);

    render(
      <MemoryRouter initialEntries={['/scans/new']}>
        <CurrentPath />
        <Routes>
          <Route path="/scans/new" element={<NewScanPage />} />
          <Route path="/scans/:scanId" element={<div>Scan details loaded</div>} />
        </Routes>
      </MemoryRouter>,
    );

    const startButton = await screen.findByRole('button', { name: /start scan/i });
    expect((startButton as HTMLButtonElement).disabled).toBe(true);

    await user.click(screen.getByRole('checkbox', {
      name: /i confirm i am authorized to assess this target/i,
    }));
    await user.click(screen.getByRole('button', { name: /test target connection/i }));
    await screen.findByText('Controlled target is reachable.');

    const countInput = screen.getByLabelText(/total test cases \(including mutations\)/i);
    fireEvent.change(countInput, { target: { value: '2' } });

    await user.click(startButton);
    await screen.findByText('Scan details loaded');

    expect(startScan).toHaveBeenCalledWith(expect.objectContaining({
      targetId: 'authorized-target',
      count: 2,
      categories: ['prompt_injection', 'jailbreak'],
      authorizationConfirmed: true,
    }));
    await waitFor(() => expect(screen.getByTestId('current-path').textContent).toBe('/scans/scan-returned-by-backend'));
  });
});
