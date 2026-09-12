/* The blocks lifted out of LiveView. They read only from props, which is what
 * made them safe to move - these tests pin that they still render the same
 * three states the tabs had inline.
 */
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { AuditTrail, ChainList, CoverageMatrix } from '../live/Panels.jsx';

const time = (ts) => new Date((ts || 0) * 1000).toISOString().slice(11, 19);

describe('ChainList', () => {
  const chain = {
    id: 'c1', severity: 'high', source: 'llm', title: 'Creds to RCE',
    summary: 'Leaked key enables command execution.',
    steps: [{ action: 'Read .env', reason: 'exposed' }, { action: 'Run command', reason: 'key valid' }],
  };

  it('renders each chain with its numbered steps', () => {
    render(<ChainList chains={[chain]} />);
    expect(screen.getByText('Creds to RCE')).toBeTruthy();
    expect(screen.getAllByText('Read .env').length).toBeGreaterThan(0);
    expect(screen.getByText('1 multi-step paths')).toBeTruthy();
  });

  it('says so when nothing chained', () => {
    render(<ChainList chains={[]} />);
    expect(screen.getByText(/No multi-step attack chains/)).toBeTruthy();
  });

  it('survives a chain with no steps', () => {
    expect(() => render(<ChainList chains={[{ id: 'x', title: 'T' }]} />)).not.toThrow();
  });
});

describe('CoverageMatrix', () => {
  it('lists catalog items against assets', () => {
    render(<CoverageMatrix covSummary={{ done: 3, pending: 1 }}
                           coverage={[{ catalog_item_id: 'RECON-DNS', asset_value: 't.example', status: 'done' }]} />);
    expect(screen.getByText('RECON-DNS')).toBeTruthy();
    // "done" appears in the summary strip and in the row's status chip.
    expect(screen.getAllByText('done').length).toBe(2);
  });

  it('explains an empty matrix rather than showing a bare table', () => {
    render(<CoverageMatrix covSummary={{}} coverage={[]} />);
    expect(screen.getByText(/Coverage builds as the run progresses/)).toBeTruthy();
    expect(screen.getByText(/Nothing run yet/)).toBeTruthy();
  });
});

describe('AuditTrail', () => {
  const audit = {
    data: { items: [{ id: 1, ts: 1700000000, action: 'engagement.run_queued', detail: { run_id: 'r1' } }] },
    loading: false, error: null, reload: () => {},
  };

  it('shows the recorded actions', () => {
    render(<AuditTrail audit={audit} time={time} />);
    expect(screen.getByText('engagement.run_queued')).toBeTruthy();
    expect(screen.getByText(/run_id=r1/)).toBeTruthy();
  });

  it('surfaces a failure rather than an empty list', () => {
    render(<AuditTrail time={time}
                       audit={{ data: null, loading: false, error: 'API down', reload: () => {} }} />);
    expect(screen.getByRole('alert').textContent).toContain('API down');
  });

  it('distinguishes an empty trail from a broken one', () => {
    render(<AuditTrail time={time}
                       audit={{ data: { items: [] }, loading: false, error: null, reload: () => {} }} />);
    expect(screen.getByText(/No actions recorded yet/)).toBeTruthy();
  });
});
