/* The findings triage screen.
 *
 * It had no test. This pins the rebuild's load-bearing decisions: the severity
 * counts double as the filter (click Critical, see only criticals), selecting a
 * row shows its detail, long evidence lives in collapsible blocks, and the
 * verdict actions call the API.
 */
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';
import Findings from '../Findings.jsx';
import { api } from '../../lib/api.js';

const ITEMS = [
  { id: 'f1', severity: 'critical', cvss: 9.8, title: 'SQL injection on /login',
    target: 'https://app.acme.com/login', status: 'confirmed', engagement: 'app.acme.com',
    dup: 2, last_seen: Date.now() / 1000, cls: 'sql_injection', category: 'injection', tool: 'sqlmap',
    desc: 'Boolean-based blind SQLi.', evidence: 'error: syntax near', poc: "' OR 1=1--" },
  { id: 'f2', severity: 'low', cvss: 3.1, title: 'Missing security header',
    target: 'https://app.acme.com/', status: 'new', engagement: 'app.acme.com',
    dup: 1, last_seen: Date.now() / 1000, cls: 'config', category: 'config', tool: 'nuclei' },
];

beforeEach(() => {
  vi.restoreAllMocks();
  // useEngagements calls this; give it one engagement, and it will select it.
  vi.spyOn(api.engagements, 'list').mockResolvedValue({ items: [{ id: 'e1', target_host: 'app.acme.com' }] });
  vi.spyOn(api.engagements, 'findings').mockResolvedValue({ items: ITEMS });
  vi.spyOn(api.engagements, 'chains').mockResolvedValue({ items: [] });
  vi.spyOn(api.findings, 'list').mockResolvedValue({ items: ITEMS });
});

async function mount() {
  let r;
  await act(async () => { r = render(<Findings />); });
  return r;
}

it('shows the severity counts as tiles', async () => {
  await mount();
  await waitFor(() => screen.getByText('SQL injection on /login'));
  const crit = screen.getByRole('button', { name: /Critical/ });
  expect(within(crit).getByText('1')).toBeTruthy();
});

it('filters when a severity tile is clicked, and clears on a second click', async () => {
  await mount();
  await waitFor(() => screen.getByText('Missing security header'));
  await userEvent.click(screen.getByRole('button', { name: /Critical/ }));
  await waitFor(() => {
    expect(screen.getByText('SQL injection on /login')).toBeTruthy();
    expect(screen.queryByText('Missing security header')).toBeNull();
  });
  expect(screen.getByRole('button', { name: /Critical/ }).getAttribute('aria-pressed')).toBe('true');
  // Click again -> back to all.
  await userEvent.click(screen.getByRole('button', { name: /Critical/ }));
  await waitFor(() => expect(screen.getByText('Missing security header')).toBeTruthy());
});

it('selecting a row shows its detail with a collapsible evidence block', async () => {
  await mount();
  await waitFor(() => screen.getByText('SQL injection on /login'));
  await userEvent.click(screen.getByText('SQL injection on /login'));
  await waitFor(() => screen.getByRole('heading', { name: /SQL injection on \/login/ }));
  // Evidence is present, and it is a collapsible block.
  expect(screen.getByRole('button', { name: /Evidence/ })).toBeTruthy();
  expect(screen.getByText('error: syntax near')).toBeTruthy();
  // Request/Response blocks are collapsed by default (this finding has none).
});

it('marks a finding as a false positive through the API', async () => {
  const setStatus = vi.spyOn(api.findings, 'setStatus').mockResolvedValue({});
  await mount();
  await waitFor(() => screen.getByText('SQL injection on /login'));
  await userEvent.click(screen.getByText('SQL injection on /login'));
  await waitFor(() => screen.getByRole('button', { name: /False positive/ }));
  await userEvent.click(screen.getByRole('button', { name: /False positive/ }));
  expect(setStatus).toHaveBeenCalledWith('f1', 'false_positive');
});

it('surfaces a load error instead of an empty table', async () => {
  vi.spyOn(api.engagements, 'findings').mockRejectedValue(new Error('backend down'));
  await mount();
  await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/backend down/));
});

it('clicking a category in the knowledge map filters the table', async () => {
  await mount();
  await waitFor(() => screen.getByText('SQL injection on /login'));
  // Both findings are listed to begin with.
  expect(screen.getByText('Missing security header')).toBeTruthy();
  // Click the "Injection" category card in the map's radiogroup.
  const map = screen.getByRole('radiogroup', { name: 'Findings map' });
  await userEvent.click(within(map).getByRole('radio', { name: /Injection/ }));
  // The config finding drops; the injection one stays.
  await waitFor(() => expect(screen.queryByText('Missing security header')).toBeNull());
  expect(screen.getByText('SQL injection on /login')).toBeTruthy();
});
