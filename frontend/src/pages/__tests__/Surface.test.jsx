/* Attack surface screen.
 *
 * Pins the chart wiring the visual pass added: the endpoints-per-host
 * histogram and the request-method donut render from the discovered hosts,
 * and selecting a host still shows its detail.
 */
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';
import Surface from '../Surface.jsx';
import { api } from '../../lib/api.js';

const SURFACE = {
  hosts: [
    { host: 'app.acme.com', https: true, source: 'crawl', tech: ['nginx', 'php'],
      ports: [{ port: 443, proto: 'tcp', service: 'https', state: 'open' }],
      endpoints: [
        { m: 'GET', path: '/', params: [], status: 200 },
        { m: 'POST', path: '/login', params: ['user', 'pass'], status: 200 },
      ] },
    { host: 'api.acme.com', https: true, source: 'dns', tech: ['express'],
      ports: [], endpoints: [{ m: 'GET', path: '/v1/health', params: [], status: 200 }] },
  ],
};

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(api.engagements, 'list').mockResolvedValue({ items: [{ id: 'e1', target_host: 'app.acme.com' }] });
  vi.spyOn(api.engagements, 'surface').mockResolvedValue(SURFACE);
});

it('renders the surface charts from discovered hosts', async () => {
  await act(async () => { render(<Surface />); });
  await waitFor(() => expect(screen.getByText('Endpoints per host (top 8)')).toBeTruthy());
  expect(screen.getByText('Request-method mix')).toBeTruthy();
  // Three endpoints total across both hosts -> donut centre total.
  const donut = document.querySelector('.chart--donut');
  expect(donut.textContent).toContain('3');
});

it('clicking a host in the surface map selects it in the detail panel', async () => {
  await act(async () => { render(<Surface />); });
  await waitFor(() => expect(screen.getByText('Surface map')).toBeTruthy());
  // app.acme.com is selected first; its detail heading shows it.
  expect(screen.getByRole('heading', { name: 'app.acme.com' })).toBeTruthy();
  const map = screen.getByRole('radiogroup', { name: 'Surface map' });
  await userEvent.click(within(map).getByRole('radio', { name: /api\.acme\.com/ }));
  await waitFor(() => expect(screen.getByRole('heading', { name: 'api.acme.com' })).toBeTruthy());
});
