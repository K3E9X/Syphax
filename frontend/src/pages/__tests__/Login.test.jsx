/* Sign-in / first-run account creation.
 *
 * Pins the strength helper (which must never contradict the rule list) and the
 * meter the create-account form shows.
 */
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';
import Login, { strength } from '../Login.jsx';

const auth = { setupRequired: true, login: vi.fn(), setup: vi.fn(), error: '', refresh: vi.fn() };
vi.mock('../../lib/auth.jsx', () => ({ useAuth: () => auth }));

beforeEach(() => { auth.setupRequired = true; auth.login.mockClear(); auth.setup.mockClear(); });

it('strength never claims more than weak while a rule is unmet', () => {
  expect(strength('short', true)).toEqual({ score: 1, label: 'weak' });
  expect(strength('', false)).toEqual({ score: 0, label: '' });
});

it('strength rewards length and variety once the rules pass', () => {
  expect(strength('correcthorse', false).label).toBe('fair'); // 12 chars, meets floor
  expect(strength('correct-horse-battery', false).score).toBeGreaterThanOrEqual(3);
  expect(strength('correct-horse-battery-staple-9', false)).toEqual({ score: 4, label: 'strong' });
});

it('shows the meter climbing as the password gets stronger', async () => {
  await act(async () => { render(<Login />); });
  const pw = screen.getByLabelText('Password');
  // A short password is blocked, so the meter reads weak.
  await userEvent.type(pw, 'abc');
  await waitFor(() => expect(document.querySelector('.pw-meter[data-score="1"]')).toBeTruthy());
  // A long, varied passphrase - matched in Confirm so no rule blocks - climbs
  // to strong. (An unmatched Confirm is itself a blocking rule, so the meter
  // stays weak until both entries agree.)
  await userEvent.clear(pw);
  await userEvent.type(pw, 'correct-horse-battery-staple-9');
  await userEvent.type(screen.getByLabelText('Confirm password'), 'correct-horse-battery-staple-9');
  await waitFor(() => expect(document.querySelector('.pw-meter[data-score="4"]')).toBeTruthy());
});
