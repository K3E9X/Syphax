/* The other accounts on this install.
 *
 * This panel exists because four endpoints did not have one. A VM shared by
 * two or three testers is the case: each gets their own password and their own
 * line in the audit log, which is the point - "who ran this scan" is not a
 * question a shared account can answer.
 */
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';
import OperatorsCard from '../OperatorsCard.jsx';
import { AuthProvider } from '../../lib/auth.jsx';
import { api } from '../../lib/api.js';

const ADMIN = { id: 'u1', username: 'lead', role: 'admin' };
const PLAIN = { id: 'u2', username: 'junior', role: 'operator' };

const USERS = {
  items: [
    { ...ADMIN, created_at: 1700000000, last_login_at: 1700100000, disabled: false },
    { ...PLAIN, created_at: 1700200000, last_login_at: null, disabled: false },
  ],
};

async function mountAs(user) {
  vi.spyOn(api.auth, 'status').mockResolvedValue({ authenticated: true, user });
  vi.spyOn(api.llm, 'readiness').mockResolvedValue({ ready: true });
  let r;
  await act(async () => {
    r = render(<AuthProvider><OperatorsCard /></AuthProvider>);
  });
  return r;
}

beforeEach(() => { vi.restoreAllMocks(); });

it('is not rendered at all for a non-admin', async () => {
  const list = vi.spyOn(api.auth, 'users').mockResolvedValue(USERS);
  const { container } = await mountAs(PLAIN);
  expect(container.textContent).toBe('');
  expect(list).not.toHaveBeenCalled();
});

it('lists the accounts and marks which one you are', async () => {
  vi.spyOn(api.auth, 'users').mockResolvedValue(USERS);
  await mountAs(ADMIN);
  await waitFor(() => screen.getByText('junior'));
  const row = screen.getByText('lead').closest('tr');
  expect(within(row).getByText('you')).toBeTruthy();
  // Never signed in is a fact worth showing, not a blank cell.
  expect(within(screen.getByText('junior').closest('tr')).getByText('never')).toBeTruthy();
});

it('offers no way to delete the account you are signed in as', async () => {
  vi.spyOn(api.auth, 'users').mockResolvedValue(USERS);
  await mountAs(ADMIN);
  await waitFor(() => screen.getByText('junior'));
  expect(within(screen.getByText('lead').closest('tr'))
    .queryByRole('button', { name: /remove/i })).toBeNull();
  expect(within(screen.getByText('junior').closest('tr'))
    .getByRole('button', { name: /remove/i })).toBeTruthy();
});

it('asks before deleting, and names who', async () => {
  vi.spyOn(api.auth, 'users').mockResolvedValue(USERS);
  const remove = vi.spyOn(api.auth, 'removeUser').mockResolvedValue({ ok: true });
  await mountAs(ADMIN);
  await waitFor(() => screen.getByText('junior'));

  await userEvent.click(within(screen.getByText('junior').closest('tr'))
    .getByRole('button', { name: /remove/i }));
  expect(remove).not.toHaveBeenCalled();

  await userEvent.click(screen.getByRole('button', { name: /delete junior/i }));
  expect(remove).toHaveBeenCalledWith('u2');
});

it('adds an operator and reloads the list', async () => {
  const list = vi.spyOn(api.auth, 'users').mockResolvedValue(USERS);
  const add = vi.spyOn(api.auth, 'addUser').mockResolvedValue({ user: PLAIN });
  await mountAs(ADMIN);
  await waitFor(() => screen.getByText('junior'));

  await userEvent.type(screen.getByLabelText(/username/i), 'newcomer');
  await userEvent.type(screen.getByLabelText(/initial password/i), 'a real passphrase');
  await userEvent.click(screen.getByRole('button', { name: /add operator/i }));

  expect(add).toHaveBeenCalledWith({
    username: 'newcomer', password: 'a real passphrase', role: 'operator',
  });
  await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
});

it('shows the server\'s refusal rather than clearing the form', async () => {
  vi.spyOn(api.auth, 'users').mockResolvedValue(USERS);
  vi.spyOn(api.auth, 'addUser').mockRejectedValue(
    new Error("the username 'junior' is already taken"));
  await mountAs(ADMIN);
  await waitFor(() => screen.getByText('junior'));

  await userEvent.type(screen.getByLabelText(/username/i), 'junior');
  await userEvent.type(screen.getByLabelText(/initial password/i), 'a real passphrase');
  await userEvent.click(screen.getByRole('button', { name: /add operator/i }));

  await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/already taken/));
  expect(screen.getByLabelText(/username/i).value).toBe('junior');
});
