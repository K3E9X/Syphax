/* Knowledge Map hero.
 *
 * Pins the load-bearing behaviour: it renders one card per category (max 5),
 * shows the confidence score, selection is a radiogroup (click + arrow keys
 * move the checked card), and the active card's high/med/low fan-out reflects
 * the selected category.
 */
import { act, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { expect, it } from 'vitest';
import KnowledgeMap from '../KnowledgeMap.jsx';

const CATS = [
  { key: 'injection', label: 'Injection', count: 8, high: 5, med: 2, low: 1 },
  { key: 'auth', label: 'Auth', count: 4, high: 1, med: 2, low: 1 },
  { key: 'config', label: 'Config', count: 3, high: 0, med: 1, low: 2 },
];

it('renders a card per category and the confidence score', () => {
  render(<KnowledgeMap categories={CATS} confidence={72} title="Findings map" />);
  const group = screen.getByRole('radiogroup');
  expect(within(group).getAllByRole('radio').length).toBe(3);
  expect(screen.getByText('72')).toBeTruthy();
});

it('caps at five categories', () => {
  const many = Array.from({ length: 8 }, (_, i) => ({ key: 'k' + i, label: 'C' + i, count: i }));
  render(<KnowledgeMap categories={many} confidence={10} />);
  expect(screen.getAllByRole('radio').length).toBe(5);
});

it('click selects a category and updates the fan-out', async () => {
  render(<KnowledgeMap categories={CATS} confidence={50} />);
  // First category active by default.
  expect(screen.getByRole('radio', { checked: true }).textContent).toContain('Injection');
  await userEvent.click(screen.getByRole('radio', { name: /Auth/ }));
  expect(screen.getByRole('radio', { checked: true }).textContent).toContain('Auth');
  // Fan-out label reflects the selected category and its share of the total.
  expect(screen.getByText(/Auth · 4 of 15/)).toBeTruthy();
});

it('arrow keys page through the cards', async () => {
  render(<KnowledgeMap categories={CATS} confidence={50} />);
  const first = screen.getByRole('radio', { name: /Injection/ });
  first.focus();
  await act(async () => { await userEvent.keyboard('{ArrowDown}'); });
  expect(screen.getByRole('radio', { checked: true }).textContent).toContain('Auth');
});

it('an activeKey outside the shown cards checks nothing and hides the fan-out', () => {
  // Controlled with a key that is not among the categories (a page whose
  // selection is drawn from a wider list). Must not mis-highlight card 0.
  render(<KnowledgeMap categories={CATS} confidence={40} activeKey="not-a-key" />);
  expect(screen.queryByRole('radio', { checked: true })).toBeNull();
  // Fan-out (which shows "<label> · N of M") is not rendered for a missing key.
  expect(screen.queryByText(/ of /)).toBeNull();
});

it('totals across all categories even when more than five are given', () => {
  const six = Array.from({ length: 6 }, (_, i) => ({ key: 'k' + i, label: 'C' + i, count: 10, high: 10, med: 0, low: 0 }));
  render(<KnowledgeMap categories={six} confidence={0} defaultActiveKey="k0" />);
  // Only 5 cards shown, but the fan-out total reflects all six (60), not 50.
  expect(screen.getByText(/of 60/)).toBeTruthy();
});
