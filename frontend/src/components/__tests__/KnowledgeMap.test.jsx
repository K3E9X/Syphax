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
