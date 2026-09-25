/* The live view - the screen an operator watches during a run.
 *
 * It had no test. This is a smoke test around the redesign's load-bearing
 * decisions: the header and KPIs render from state, the agent console is
 * PERMANENT (a rail, no longer a tab you leave to read a finding), the primary
 * action calls the API, and an approval shows as a banner rather than hiding
 * behind a tab.
 */
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import LiveView from '../LiveView.jsx';
import { api } from '../../lib/api.js';

// The view opens a WebSocket; jsdom may not, so stub a no-op one.
class FakeWS {
  constructor() { this.readyState = 0; }
  close() {}
  send() {}
}

const STATE = {
  engagement: { id: 'e1', target_host: 'app.acme.com' },
  run: { status: 'running', phase: 'vuln_analysis', iterations: 3, jobs_launched: 12 },
  technologies: ['nginx', 'PHP'],
  llm_usage: { total_tokens: 4200, cost_usd: 0.0123 },
  validation_summary: { confirmed: 2, false_positive_rate_pct: 8 },
  assets: [{ kind: 'endpoint', value: 'https://app.acme.com/login', source: 'katana', has_params: true, is_https: true }],
  jobs: [],
  coverage: [],
  validated_findings: [
    { id: 'f1', title: 'SQL injection on /login', target: 'https://app.acme.com/login',
      severity: 'critical', status: 'confirmed', confidence: 0.95, proven: true,
      tool: 'sqlmap', vuln_class: 'sql_injection', category: 'injection' },
  ],
  chains: [],
};

function mountAt() {
  return render(
    <MemoryRouter initialEntries={['/engagements/e1/live']}>
      <Routes><Route path="/engagements/:id/live" element={<LiveView />} /></Routes>
    </MemoryRouter>);
}

beforeEach(() => {
  vi.restoreAllMocks();
  global.WebSocket = FakeWS;
  vi.spyOn(api.engagements, 'state').mockResolvedValue(STATE);
  vi.spyOn(api.engagements, 'approvals').mockResolvedValue({ items: [] });
  vi.spyOn(api.engagements, 'memory').mockResolvedValue({ lessons: [] });
  vi.spyOn(api.engagements, 'events').mockResolvedValue({ items: [] });
  vi.spyOn(api.engagements, 'usage').mockResolvedValue({});
  vi.spyOn(api.audit, 'list').mockResolvedValue({ items: [] });
});

it('renders the header, host and running status from state', async () => {
  await act(async () => { mountAt(); });
  await waitFor(() => expect(screen.getByText('app.acme.com')).toBeTruthy());
  expect(screen.getByRole('heading', { name: /live view/i })).toBeTruthy();
  expect(screen.getByText('running')).toBeTruthy();
});

it('shows the KPIs from the validation summary', async () => {
  await act(async () => { mountAt(); });
  await waitFor(() => screen.getByText('Confirmed'));
  const confirmed = screen.getByText('Confirmed').closest('.stat');
  expect(confirmed.textContent).toContain('2');
});

it('keeps the agent console permanent, not a tab', async () => {
  await act(async () => { mountAt(); });
  await waitFor(() => screen.getByText('Agent console'));
  // No "Console" tab button — the console is a fixed rail now.
  expect(screen.queryByRole('button', { name: /^Console$/ })).toBeNull();
  // And the findings tab is there.
  expect(screen.getByRole('button', { name: /Findings/ })).toBeTruthy();
});

it('shows findings and lets you switch the drill-down without losing the console', async () => {
  await act(async () => { mountAt(); });
  await waitFor(() => screen.getByText('SQL injection on /login'));
  await userEvent.click(screen.getByRole('button', { name: /Assets/ }));
  await waitFor(() => screen.getByText('Discovered assets'));
  // The console is still on screen while Assets is open.
  expect(screen.getByText('Agent console')).toBeTruthy();
});

it('Stop calls the API while a run is active', async () => {
  const stop = vi.spyOn(api.engagements, 'stop').mockResolvedValue({});
  await act(async () => { mountAt(); });
  await waitFor(() => screen.getByRole('button', { name: /^Stop$/ }));
  await userEvent.click(screen.getByRole('button', { name: /^Stop$/ }));
  expect(stop).toHaveBeenCalledWith('e1');
});

describe('an approval', () => {
  it('shows as a banner with approve and deny, not behind a tab', async () => {
    vi.spyOn(api.engagements, 'approvals').mockResolvedValue({
      items: [{ id: 'ap1', decision: null, summary: 'Approve exploitation phase: sqlmap on 1 target',
                tools: ['sqlmap'], targets: ['app.acme.com'] }],
    });
    await act(async () => { mountAt(); });
    await waitFor(() => screen.getByText(/approval required to continue/i));
    expect(screen.getByRole('button', { name: /approve exploitation/i })).toBeTruthy();
    expect(screen.getByRole('button', { name: /^Deny$/ })).toBeTruthy();
  });
});
