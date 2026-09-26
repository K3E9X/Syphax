/* Methodology coverage screen.
 *
 * Pins the chart wiring the visual pass added: with an engagement selected the
 * coverage radar (from the engagement's per-axis radar) and the status-mix
 * donut both render, and the category list still shows.
 */
import { act, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import Methodology from '../Methodology.jsx';
import { api } from '../../lib/api.js';

const COVERAGE = {
  categories: [
    { cat: 'Authentication', wstg: 'WSTG-ATHN', items: [
      { id: 'ATHN-01', name: 'Weak lockout', attack: ['T1110'], asset: 'app.acme.com', status: 'done', hit: true },
      { id: 'ATHN-02', name: 'Default creds', attack: [], asset: 'app.acme.com', status: 'queued', hit: false },
    ] },
  ],
};

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(api.engagements, 'list').mockResolvedValue({ items: [{ id: 'e1', target_host: 'app.acme.com', radar: [80, 66, 72, 75, 66, 55] }] });
  vi.spyOn(api.engagements, 'coverage').mockResolvedValue(COVERAGE);
});

it('renders the coverage radar and status-mix donut', async () => {
  await act(async () => { render(<Methodology />); });
  await waitFor(() => expect(screen.getByText('Coverage by axis (WSTG)')).toBeTruthy());
  expect(screen.getByText('Test status mix')).toBeTruthy();
  // The radar axis readout shows the Recon percentage from the engagement.
  expect(screen.getByText('80%')).toBeTruthy();
  // The category matrix still lists the WSTG group (also appears in the map).
  expect(document.querySelector('.cat__name').textContent).toBe('Authentication');
});
