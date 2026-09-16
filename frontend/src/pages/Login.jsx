import { useEffect, useRef, useState } from 'react';
import { useAuth } from '../lib/auth.jsx';
import { Notice } from '../components/ui.jsx';
import logoMark from '../assets/logo-mark.svg';

// Mirrors app/auth/passwords.py. Duplicated on purpose: the server is the one
// that decides, and it re-checks every rule - this copy only exists so the
// operator sees the problem while typing instead of after a round-trip.
const MIN_LENGTH = 12;

function localProblems(username, password, confirm) {
  const out = [];
  if (password.length < MIN_LENGTH) out.push(`at least ${MIN_LENGTH} characters`);
  if (username && password.toLowerCase().includes(username.trim().toLowerCase())) {
    out.push('must not contain the username');
  }
  if (password && new Set(password).size < 5) out.push('too few distinct characters');
  if (confirm !== null && password !== confirm) out.push('the two entries do not match');
  return out;
}

/**
 * The sign-in screen, and - on a fresh install - the screen that creates the
 * first account.
 *
 * One component for both because they are the same form with different copy,
 * and because keeping them together makes it obvious that the setup branch is
 * reachable in exactly one state: `setupRequired`, which the backend stops
 * reporting the moment an account exists.
 */
export default function Login() {
  const { setupRequired, login, setup, error: statusError, refresh } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const first = useRef(null);

  useEffect(() => { first.current?.focus(); }, []);
  useEffect(() => { setError(''); }, [setupRequired]);

  const problems = setupRequired ? localProblems(username, password, confirm) : [];
  const canSubmit = username.trim() && password && !busy
    && (!setupRequired || problems.length === 0);

  async function onSubmit(e) {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError('');
    try {
      if (setupRequired) await setup(username.trim(), password);
      else await login(username.trim(), password);
    } catch (err) {
      setError(err.message);
      setPassword('');
      setConfirm('');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth">
      <form className="auth__card" onSubmit={onSubmit}>
        <div className="auth__brand">
          <img src={logoMark} alt="" width="26" height="26" />
          <span className="auth__wm">syphax</span>
        </div>

        <h1 className="auth__title">
          {setupRequired ? 'Create the operator account' : 'Sign in'}
        </h1>
        <p className="auth__sub">
          {setupRequired
            ? 'This install has no account yet. The account you create here is the '
              + 'only way in, and this page closes permanently once it exists.'
            : 'This tool holds captured sessions and can bring up a VPN. It does '
              + 'not run without an account.'}
        </p>

        {/* A backend that is unreachable must not look like a rejected
            password - the operator would keep retyping a correct one. */}
        <Notice kind="warn" message={statusError} onRetry={refresh} />
        <Notice kind="error" message={error} />

        <div className="field">
          <label className="field__label" htmlFor="auth-username">Username</label>
          <input
            id="auth-username"
            ref={first}
            className="input"
            autoComplete="username"
            autoCapitalize="none"
            spellCheck="false"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>

        <div className="field">
          <label className="field__label" htmlFor="auth-password">Password</label>
          <input
            id="auth-password"
            className="input"
            type="password"
            autoComplete={setupRequired ? 'new-password' : 'current-password'}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          {setupRequired && (
            <span className="field__hint">
              At least {MIN_LENGTH} characters. A passphrase you will remember beats
              a short string with punctuation in it.
            </span>
          )}
        </div>

        {setupRequired && (
          <div className="field">
            <label className="field__label" htmlFor="auth-confirm">Confirm password</label>
            <input
              id="auth-confirm"
              className="input"
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
            />
          </div>
        )}

        {setupRequired && password && problems.length > 0 && (
          <ul className="auth__problems">
            {problems.map((p) => <li key={p}>{p}</li>)}
          </ul>
        )}

        <button className="btn auth__submit" type="submit" disabled={!canSubmit}>
          {busy ? 'Working…' : setupRequired ? 'Create account and continue' : 'Sign in'}
        </button>

        {setupRequired && (
          <p className="auth__foot">
            Provisioning this from a script? Set <code>SYPHAX_ADMIN_USER</code> and{' '}
            <code>SYPHAX_ADMIN_PASSWORD</code> before the first start and this
            page is skipped.
          </p>
        )}
      </form>
    </div>
  );
}
