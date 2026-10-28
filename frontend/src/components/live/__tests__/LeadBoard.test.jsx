/* The exploitation blackboard, on screen.
 *
 * The whole agentic layer was invisible: syphax grew a blackboard, a
 * strategist reading it and a consumption loop, and the only way to see any
 * of it was a psql prompt or the console scrollback. An API route existed and
 * nothing in the frontend called it.
 */
import { render, screen, within } from '@testing-library/react';
import { expect, it } from 'vitest';
import { LeadBoard } from '../Panels.jsx';

const LEADS = [
  { id: 1, kind: 'injectable', value: 'https://t/p?id=1', confidence: 0.9,
    source: 'sqlmap', grants_identity: false, consumed_by: ['sqlmap'] },
  { id: 2, kind: 'unauth_endpoint', value: 'https://t/password-reset',
    confidence: 0.8, source: 'api_inventory', grants_identity: false,
    consumed_by: [] },
  { id: 3, kind: 'session', value: 'PHP…bc', confidence: 0.95,
    source: 'auth-brute', grants_identity: true, consumed_by: [] },
];

it('lists what the run has established', () => {
  render(<LeadBoard leads={LEADS} />);
  expect(screen.getByText('injectable')).toBeTruthy();
  expect(screen.getByText('https://t/password-reset')).toBeTruthy();
  expect(screen.getByText('auth-brute')).toBeTruthy();
});

it('says how much is still untouched', () => {
  render(<LeadBoard leads={LEADS} />);
  expect(screen.getByText(/3 chainable fact\(s\) · 2 not yet acted on/)).toBeTruthy();
});

it('shows which leads have already been run against', () => {
  // "found by" and "acted on by" are different columns and can hold the same
  // tool - sqlmap confirmed this injection point AND has since run on it - so
  // the assertion has to name the column, not just the text.
  render(<LeadBoard leads={LEADS} />);
  const worked = screen.getByText('https://t/p?id=1').closest('tr');
  const cells = within(worked).getAllByRole('cell');
  expect(cells[3].textContent).toBe('sqlmap');   // found by
  expect(cells[4].textContent).toBe('sqlmap');   // acted on by

  const fresh = screen.getByText('https://t/password-reset').closest('tr');
  expect(within(fresh).getAllByRole('cell')[3].textContent).toBe('api_inventory');
  expect(within(fresh).getByText('not yet')).toBeTruthy();
});

it('dims a worked lead rather than hiding it', () => {
  // The fact is still true and still in the report; it is just no longer the
  // thing the strategist reaches for first.
  render(<LeadBoard leads={LEADS} />);
  const worked = screen.getByText('https://t/p?id=1').closest('tr');
  expect(worked.className).toContain('row--muted');
  const fresh = screen.getByText('https://t/password-reset').closest('tr');
  expect(fresh.className || '').not.toContain('row--muted');
});

it('marks an identity lead, and never reprints one', () => {
  render(<LeadBoard leads={LEADS} />);
  const tag = screen.getByText('session');
  expect(tag.className).toContain('ftag--id');
  expect(tag.getAttribute('title')).toMatch(/redacted/);
  expect(screen.getByText('PHP…bc')).toBeTruthy();
});

it('an empty board says what that means', () => {
  // During a run this is information, not a blank: it says nothing found so
  // far was chainable, so the plan is the plain methodology order.
  render(<LeadBoard leads={[]} />);
  expect(screen.getByText(/Nothing on the board yet/)).toBeTruthy();
  expect(screen.getByText(/plain methodology order/)).toBeTruthy();
});

it('renders confidence as a percentage', () => {
  render(<LeadBoard leads={LEADS} />);
  expect(screen.getByText('90%')).toBeTruthy();
  expect(screen.getByText('95%')).toBeTruthy();
});

it('survives a lead with missing fields', () => {
  render(<LeadBoard leads={[{ id: 9, kind: 'host', value: 'x' }]} />);
  expect(screen.getByText('0%')).toBeTruthy();
  expect(screen.getByText('-')).toBeTruthy();
});
