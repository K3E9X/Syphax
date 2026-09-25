/* Proxy capture screen.
 *
 * Pins the chart wiring the visual pass added: from the captured flows a
 * response-code donut and a request-method histogram render, and the flow
 * table still lists the captured rows.
 */
import { act, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import Proxy from '../Proxy.jsx';
import { api } from '../../lib/api.js';

const FLOWS = [
  { id: '1', timestamp: 1700000000, method: 'GET', status_code: 200, host: 'app.acme.com', path: '/', response_size: 512, duration_ms: 40 },
  { id: '2', timestamp: 1700000001, method: 'POST', status_code: 404, host: 'app.acme.com', path: '/login', response_size: 128, duration_ms: 80 },
  { id: '3', timestamp: 1700000002, method: 'GET', status_code: 500, host: 'app.acme.com', path: '/boom', response_size: 64, duration_ms: 120 },
];

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(api.proxy, 'status').mockResolvedValue({ running: true, port: 8080, flow_count: 3 });
  vi.spyOn(api.proxy, 'hosts').mockResolvedValue({ items: [{ host: 'app.acme.com' }] });
  vi.spyOn(api.proxy, 'flows').mockResolvedValue({ items: FLOWS });
  vi.spyOn(api.engagements, 'list').mockResolvedValue({ items: [{ id: 'e1', status: 'authorized', target_host: 'app.acme.com' }] });
});

it('renders the response-code and method charts from captured flows', async () => {
  await act(async () => { render(<Proxy />); });
  await waitFor(() => expect(screen.getByText('Response codes')).toBeTruthy());
  expect(screen.getByText('Request-method mix')).toBeTruthy();
  // Donut centre totals the three flows.
  const donut = document.querySelector('.chart--donut');
  expect(donut.textContent).toContain('3');
  // The flow table still shows a captured path.
  expect(screen.getByText('/login')).toBeTruthy();
});
