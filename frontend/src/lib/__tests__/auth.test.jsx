/* The sign-in shell.
 *
 * The behaviours pinned here are the ones whose regression is invisible until
 * it matters:
 *
 *   1. nothing behind the gate renders before we know who is asking - a flash
 *      of the real UI is a flash of someone else's engagement data;
 *   2. a fresh install lands on the SETUP form, not the login form;
 *   3. a 401 from any call - including a background poll - returns to the
 *      login screen instead of leaving eleven panels showing their own error;
 *   4. an unreachable backend is distinguishable from a rejected password.
 */
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthProvider, useAuth } from '../auth.jsx';
import Gate from '../../components/Gate.jsx';
import { UNAUTHENTICATED_EVENT } from '../api.js';
import { api } from '../api.js';

const USER = { id: 'u1', username: 'operator', role: 'admin' };

function Secret() {
  return <div>engagement data</div>;
}

async function mount(ui) {
  let r;
  await act(async () => { r = render(ui); });
  return r;
}

const shell = (
  <AuthProvider>
    <Gate><Secret /></Gate>
  </AuthProvider>
);

beforeEach(() => {
  vi.restoreAllMocks();
  // The gate checks the model configuration after the session. These tests are
  // about the session half; the other half has its own file.
  vi.spyOn(api.llm, 'readiness').mockResolvedValue({ ready: true });
});

describe('the gate', () => {
  it('renders nothing behind it until the status call answers', async () => {
    let resolve;
    vi.spyOn(api.auth, 'status').mockReturnValue(new Promise((r) => { resolve = r; }));
    await mount(shell);
    expect(screen.queryByText('engagement data')).toBeNull();
    expect(screen.getByText(/loading/i)).toBeTruthy();
    await act(async () => { resolve({ authenticated: true, user: USER }); });
    await waitFor(() => expect(screen.getByText('engagement data')).toBeTruthy());
  });

  it('lets a signed-in operator through', async () => {
    vi.spyOn(api.auth, 'status').mockResolvedValue({ authenticated: true, user: USER });
    await mount(shell);
    await waitFor(() => expect(screen.getByText('engagement data')).toBeTruthy());
  });

  it('shows the login form when there is no session', async () => {
    vi.spyOn(api.auth, 'status').mockResolvedValue({
      authenticated: false, user: null, setup_required: false,
    });
    await mount(shell);
    await waitFor(() => expect(screen.getByRole('heading', { name: /sign in/i })).toBeTruthy());
    expect(screen.queryByText('engagement data')).toBeNull();
    // No confirm field: that one only belongs on the setup form.
    expect(screen.queryByLabelText(/confirm/i)).toBeNull();
  });

  it('shows the SETUP form on a fresh install, not the login form', async () => {
    vi.spyOn(api.auth, 'status').mockResolvedValue({
      authenticated: false, user: null, setup_required: true,
    });
    await mount(shell);
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: /create the operator account/i })).toBeTruthy());
    expect(screen.getByLabelText(/confirm password/i)).toBeTruthy();
  });
});

describe('signing in', () => {
  it('sends the credentials and reveals the app', async () => {
    vi.spyOn(api.auth, 'status').mockResolvedValue({ authenticated: false, user: null });
    const login = vi.spyOn(api.auth, 'login').mockResolvedValue({ user: USER });
    await mount(shell);
    await waitFor(() => screen.getByRole('heading', { name: /sign in/i }));

        await userEvent.type(screen.getByLabelText(/username/i), 'operator');
    await userEvent.type(screen.getByLabelText(/^password$/i), 'a real passphrase');
    await userEvent.click(screen.getByRole('button', { name: /sign in/i }));

    expect(login).toHaveBeenCalledWith('operator', 'a real passphrase');
    await waitFor(() => expect(screen.getByText('engagement data')).toBeTruthy());
  });

  it('shows the rejection and clears the password field', async () => {
    vi.spyOn(api.auth, 'status').mockResolvedValue({ authenticated: false, user: null });
    vi.spyOn(api.auth, 'login').mockRejectedValue(new Error('invalid username or password'));
    await mount(shell);
    await waitFor(() => screen.getByRole('heading', { name: /sign in/i }));

        await userEvent.type(screen.getByLabelText(/username/i), 'operator');
    await userEvent.type(screen.getByLabelText(/^password$/i), 'wrong passphrase');
    await userEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => expect(screen.getByRole('alert').textContent)
      .toMatch(/invalid username or password/i));
    expect(screen.getByLabelText(/^password$/i).value).toBe('');
  });
});

describe('creating the first account', () => {
  beforeEach(() => {
    vi.spyOn(api.auth, 'status').mockResolvedValue({
      authenticated: false, user: null, setup_required: true,
    });
  });

  it('refuses to submit a password the server would reject anyway', async () => {
    const setup = vi.spyOn(api.auth, 'setup').mockResolvedValue({ user: USER });
    await mount(shell);
    await waitFor(() => screen.getByRole('heading', { name: /create the operator account/i }));

        await userEvent.type(screen.getByLabelText(/username/i), 'operator');
    await userEvent.type(screen.getByLabelText(/^password$/i), 'short');
    await userEvent.type(screen.getByLabelText(/confirm password/i), 'short');

    expect(screen.getByRole('button', { name: /create account/i }).disabled).toBe(true);
    expect(setup).not.toHaveBeenCalled();
  });

  it('refuses a mismatched confirmation', async () => {
    await mount(shell);
    await waitFor(() => screen.getByRole('heading', { name: /create the operator account/i }));
        await userEvent.type(screen.getByLabelText(/username/i), 'operator');
    await userEvent.type(screen.getByLabelText(/^password$/i), 'a real passphrase');
    await userEvent.type(screen.getByLabelText(/confirm password/i), 'a real passphras');
    expect(screen.getByRole('button', { name: /create account/i }).disabled).toBe(true);
  });

  it('creates the account and goes straight in', async () => {
    const setup = vi.spyOn(api.auth, 'setup').mockResolvedValue({ user: USER });
    await mount(shell);
    await waitFor(() => screen.getByRole('heading', { name: /create the operator account/i }));
        await userEvent.type(screen.getByLabelText(/username/i), 'operator');
    await userEvent.type(screen.getByLabelText(/^password$/i), 'a real passphrase');
    await userEvent.type(screen.getByLabelText(/confirm password/i), 'a real passphrase');
    await userEvent.click(screen.getByRole('button', { name: /create account/i }));
    expect(setup).toHaveBeenCalledWith('operator', 'a real passphrase');
    await waitFor(() => expect(screen.getByText('engagement data')).toBeTruthy());
  });
});

describe('losing the session', () => {
  it('a 401 from any call drops back to the login screen', async () => {
    vi.spyOn(api.auth, 'status').mockResolvedValue({ authenticated: true, user: USER });
    await mount(shell);
    await waitFor(() => screen.getByText('engagement data'));

    // A background poll on a page nobody is looking at hits a 401.
    await act(async () => {
      window.dispatchEvent(new CustomEvent(UNAUTHENTICATED_EVENT, { detail: {} }));
    });

    await waitFor(() => expect(screen.getByRole('heading', { name: /sign in/i })).toBeTruthy());
    expect(screen.queryByText('engagement data')).toBeNull();
  });

  it('signing out clears the session even if the request fails', async () => {
    vi.spyOn(api.auth, 'status').mockResolvedValue({ authenticated: true, user: USER });
    vi.spyOn(api.auth, 'logout').mockRejectedValue(new Error('network down'));

    function SignOut() {
      const { logout, user } = useAuth();
      return <button onClick={logout}>{user ? 'sign out' : 'gone'}</button>;
    }
    await mount(<AuthProvider><SignOut /></AuthProvider>);
    await waitFor(() => screen.getByRole('button', { name: 'sign out' }));
    await userEvent.click(screen.getByRole('button'));
    await waitFor(() => expect(screen.getByRole('button', { name: 'gone' })).toBeTruthy());
  });
});

describe('an unreachable backend', () => {
  it('is not presented as a rejected password', async () => {
    vi.spyOn(api.auth, 'status').mockRejectedValue(
      new Error('database unavailable; the backend is still starting'));
    await mount(shell);
    await waitFor(() => screen.getByRole('heading', { name: /sign in/i }));
    expect(screen.getByRole('status').textContent).toMatch(/database unavailable/i);
  });
});
