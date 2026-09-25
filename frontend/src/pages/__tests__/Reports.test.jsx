/* The report builder.
 *
 * Pins the rebuild's load-bearing decisions: a table of contents jumps to
 * sections, the KPI strip and severity distribution render from the state, the
 * Executive template collapses to a compact register while Technical shows
 * expandable entries with evidence, and expand-all opens every finding.
 */
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';
import Reports from '../Reports.jsx';
import { api } from '../../lib/api.js';

const STATE = {
  engagement: { id: 'e1', target_url: 'https://app.acme.com', target_host: 'app.acme.com',
    scope_hosts: ['app.acme.com'], verification_method: 'dns-txt' },
  validated_findings: [
    { id: 'f1', severity: 'critical', title: 'SQL injection on /login', target: 'https://app.acme.com/login',
      status: 'confirmed', vuln_class: 'sql_injection', tool: 'sqlmap', evidence: 'error: syntax near',
      poc: "' OR 1=1--", proven: true, category: 'injection' },
    { id: 'f2', severity: 'low', title: 'Missing security header', target: 'https://app.acme.com/',
      status: 'new', vuln_class: 'config', tool: 'nuclei', evidence: '', poc: '' },
    { id: 'f3', severity: 'info', title: 'False positive', target: 'https://app.acme.com/x',
      status: 'false_positive', vuln_class: 'noise', tool: 'nuclei' },
  ],
  chains: [{ id: 'c1', title: 'Auth bypass to RCE', severity: 'critical', steps: [{ action: 'login bypass' }, { action: 'upload shell' }] }],
  validation_summary: { confirmed: 1, likely: 1 },
  coverage_summary: { done: 8, skipped: 2 },
  technologies: ['nginx', 'php'],
  assets: [{ kind: 'endpoint', value: '/login', has_params: true, is_https: true, source: 'crawl' }],
};

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(api.engagements, 'list').mockResolvedValue({ items: [{ id: 'e1', target_host: 'app.acme.com', target_url: 'https://app.acme.com' }] });
  vi.spyOn(api.engagements, 'state').mockResolvedValue(STATE);
});

async function mount() {
  let r;
  await act(async () => { r = render(<Reports />); });
  await waitFor(() => expect(screen.getByText('Web Application Penetration Test')).toBeTruthy());
  return r;
}

it('renders a table of contents and the KPI strip', async () => {
  await mount();
  const toc = screen.getByLabelText('Report sections');
  expect(within(toc).getByText('Testing coverage')).toBeTruthy();
  // false_positive is excluded, so two findings count.
  expect(within(toc).getByText('Findings (2)')).toBeTruthy();
  // KPI strip includes a coverage figure (8 done of 10 = 80%).
  const kpis = document.querySelector('.rep-kpis');
  expect(within(kpis).getByText('coverage')).toBeTruthy();
  expect(within(kpis).getByText('80')).toBeTruthy();
});

it('technical template shows expandable entries; expand-all opens evidence', async () => {
  await mount();
  // Technical is the default; the finding entry is collapsed until opened.
  expect(screen.queryByText('error: syntax near')).toBeNull();
  await userEvent.click(screen.getByText('Expand all'));
  await waitFor(() => expect(screen.getByText('error: syntax near')).toBeTruthy());
  // proven badge is surfaced on the oracle-confirmed finding.
  expect(screen.getByText('proven')).toBeTruthy();
});

it('executive template collapses to a compact register', async () => {
  await mount();
  await userEvent.click(screen.getByText('Executive'));
  // The register is a table with a Class column; no expand-all control.
  await waitFor(() => expect(screen.getByText('Class')).toBeTruthy());
  expect(screen.queryByText('Expand all')).toBeNull();
  // Attack surface is technical-only, so it drops from the TOC.
  const toc = screen.getByLabelText('Report sections');
  expect(within(toc).queryByText('Attack surface')).toBeNull();
});
