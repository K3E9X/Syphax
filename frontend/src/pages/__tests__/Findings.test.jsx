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
  vi.spyOn(api.findings, 'list').mockRejectedValue(new Error('backend down'));
  await mount();
  await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/backend down/));
});

it('surfaces a failure to list engagements', async () => {
  vi.spyOn(api.engagements, 'list').mockRejectedValue(new Error('no engagements'));
  await mount();
  await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/no engagements/));
});

it('asks the ENRICHED endpoint, filtered to the selected engagement', async () => {
  /* The page used to call /api/engagements/{id}/findings on the default view,
   * which returns the raw ValidatedFinding and flattens nothing out of
   * metadata. Every detail block rendered empty, every row showed CVSS 0.0 in
   * the low-severity colour, the knowledge map collapsed to one "Other" card,
   * and `status` was the validation verdict rather than the triage state - so
   * the triage chips emptied the table and "Mark reported" looked like a no-op.
   *
   * This suite could never catch it: it mocked the thin endpoint with the
   * ENRICHED shape. So the assertion is on which endpoint is called. */
  const list = vi.spyOn(api.findings, 'list').mockResolvedValue({ items: ITEMS });
  const thin = vi.spyOn(api.engagements, 'findings');
  await mount();
  await waitFor(() => screen.getByText('SQL injection on /login'));
  expect(list).toHaveBeenCalledWith(expect.objectContaining({ engagement: 'e1' }));
  expect(thin).not.toHaveBeenCalled();
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

/* The detail panel has to say what to DO about a finding, not only what is
 * wrong with it. remediation, CWE, WSTG, OWASP API and ATT&CK were all in the
 * backend's class mapping already and only the report ever used them. */

const RICH = [{
  id: 'f3', severity: 'high', cvss: 8.1, title: 'IDOR on /invoice',
  target: 'https://app.acme.com/invoice?id=1', status: 'confirmed',
  engagement: 'app.acme.com', cls: 'idor', category: 'access_control',
  tool: 'logic', dup: 3, first_seen: Date.now() / 1000 - 86400,
  last_seen: Date.now() / 1000,
  targets: ['https://app.acme.com/invoice?id=1',
            'https://app.acme.com/invoice?id=2',
            'https://app.acme.com/order?id=7'],
  remediation: 'Enforce object-level authorization server-side.',
  cwe: 'CWE-639', wstg: 'WSTG-ATHZ-04', owasp_api: 'API1:2023',
  attack: ['T1190'],
}];

async function mountRich(items = RICH) {
  vi.spyOn(api.findings, 'list').mockResolvedValue({ items });
  const r = await mount();
  await waitFor(() => screen.getByText('IDOR on /invoice'));
  await userEvent.click(screen.getByText('IDOR on /invoice'));
  return r;
}

it('shows how to fix the finding', async () => {
  await mountRich();
  expect(screen.getByText('How to fix it')).toBeTruthy();
  expect(screen.getByText(/Enforce object-level authorization/)).toBeTruthy();
});

it('shows the standards references, with links out', async () => {
  await mountRich();
  const cwe = screen.getByText('CWE-639');
  expect(cwe.getAttribute('href')).toBe('https://cwe.mitre.org/data/definitions/639.html');
  expect(screen.getByText('WSTG-ATHZ-04')).toBeTruthy();
  expect(screen.getByText('OWASP API1:2023')).toBeTruthy();
  const attack = screen.getByText(/ATT&CK T1190/);
  expect(attack.getAttribute('href')).toBe('https://attack.mitre.org/techniques/T1190/');
});

it('a sub-technique id becomes the right ATT&CK path', async () => {
  await mountRich([{ ...RICH[0], attack: ['T1059.007'] }]);
  expect(screen.getByText(/ATT&CK T1059\.007/).getAttribute('href'))
    .toBe('https://attack.mitre.org/techniques/T1059/007/');
});

it('the occurrence count is no longer a dead number', async () => {
  await mountRich();
  // The affected URLs are reachable from the panel, not just counted.
  await userEvent.click(screen.getByRole('button', { name: /Affected \(3\)/ }));
  expect(screen.getByText(/app\.acme\.com\/order\?id=7/)).toBeTruthy();
});

it('shows first seen as well as last seen', async () => {
  await mountRich();
  expect(screen.getByText('First seen')).toBeTruthy();
  expect(screen.getByText('Last seen')).toBeTruthy();
});

it('a single-target finding does not get an Affected block', async () => {
  await mountRich([{ ...RICH[0], dup: 1, targets: ['https://app.acme.com/invoice?id=1'] }]);
  expect(screen.queryByRole('button', { name: /Affected/ })).toBeNull();
});

it('a class with no OWASP API mapping shows no OWASP tag', async () => {
  // "" is a real answer: the API Top 10 does not cover every web weakness,
  // and naming the nearest item would send a reader to the wrong control.
  await mountRich([{ ...RICH[0], owasp_api: '' }]);
  expect(screen.queryByText(/^OWASP /)).toBeNull();
  expect(screen.getByText('CWE-639')).toBeTruthy();
});

/* A PoC chooses its own exit code, so a clean sandbox run is not by itself
 * proof. The panel used to call every one of them "the strongest proof there
 * is", which was a false claim in the place the operator reads verdicts. */

const EXPLOITED = (oracle) => [{
  ...RICH[0], id: 'f4',
  exploitation: { repo: 'authored', path: 'idor.py', exit_code: 0, auto: true,
                  stdout: "invoice #2 belongs to another user", oracle },
}];

it('says a corroborated PoC is the strongest proof', async () => {
  await mountRich(EXPLOITED({ outcome: 'held', expect: 'other.user@example.com' }));
  expect(screen.getByText(/independently\s+re-requested/)).toBeTruthy();
  expect(screen.getByText(/strongest proof there is/)).toBeTruthy();
});

it('does not claim proof for an uncorroborated PoC', async () => {
  await mountRich(EXPLOITED(null));
  expect(screen.queryByText(/strongest proof there is/)).toBeNull();
  expect(screen.getByText(/not an\s+independent confirmation/)).toBeTruthy();
});

it('does not claim proof when the oracle refuted the claim', async () => {
  await mountRich(EXPLOITED({ outcome: 'did_not_hold' }));
  expect(screen.queryByText(/strongest proof there is/)).toBeNull();
});
