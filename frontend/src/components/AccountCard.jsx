import { useEffect, useState } from 'react';
import { api } from '../lib/api.js';
import { useAuth } from '../lib/auth.jsx';
import { Notice } from './ui.jsx';

function when(ts) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleString();
}

/**
 * The operator's own account: change the password, see the sessions that are
 * live, end them all.
 *
 * The session list is the part that earns its place. An operator who exposes
 * this on a VM has no other way to notice a second browser holding a valid
 * cookie, and a session they do not recognise is the signal that matters most.
 */
export default function AccountCard() {
  const { user } = useAuth();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [ok, setOk] = useState('');
  const [sessions, setSessions] = useState(null);
  const [sessionsError, setSessionsError] = useState('');

  const loadSessions = () => api.auth.sessions()
    .then((r) => { setSessions(r?.items || []); setSessionsError(''); })
    .catch((e) => { setSessions([]); setSessionsError(e.message); });

  useEffect(() => { loadSessions(); }, []);

  const mismatch = confirm !== '' && next !== confirm;
  const canSubmit = current && next && next === confirm && !busy;

  async function change(e) {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true); setError(''); setOk('');
    try {
      await api.auth.changePassword(current, next);
      setOk('Password changed. Every other session was signed out.');
      setCurrent(''); setNext(''); setConfirm('');
      loadSessions();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function revokeAll() {
    setError(''); setOk('');
    try {
      await api.auth.revokeSessions();
      // Including this one - the next request will 401 and the shell returns
      // to the login screen on its own.
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="card set-full">
      <div className="card__head">
        <span className="card__title">Account</span>
        <span className="card__meta">{user ? `${user.username} · ${user.role}` : ''}</span>
      </div>
      <div className="card__body">
        <Notice kind="error" message={error} />
        <Notice kind="info" message={ok} />

        <form onSubmit={change}>
          <div className="router-row">
            <div className="router-row__role">password<small>change</small></div>
            <div className="field">
              <label className="field__label" htmlFor="pw-current">Current</label>
              <input id="pw-current" className="input" type="password" autoComplete="current-password"
                     value={current} onChange={(e) => setCurrent(e.target.value)} />
            </div>
            <div className="field">
              <label className="field__label" htmlFor="pw-next">New</label>
              <input id="pw-next" className="input" type="password" autoComplete="new-password"
                     value={next} onChange={(e) => setNext(e.target.value)} />
            </div>
          </div>
          <div className="field">
            <label className="field__label" htmlFor="pw-confirm">Confirm new password</label>
            <input id="pw-confirm" className="input" type="password" autoComplete="new-password"
                   value={confirm} onChange={(e) => setConfirm(e.target.value)} />
            {mismatch && <span className="field__hint">The two entries do not match.</span>}
          </div>
          <button className="btn" type="submit" disabled={!canSubmit}>
            {busy ? 'Working…' : 'Change password'}
          </button>
        </form>

        <div className="io-label">Live sessions</div>
        {sessionsError && <Notice kind="error" message={sessionsError} onRetry={loadSessions} />}
        {sessions === null && <div className="empty empty--loading">Loading…</div>}
        {sessions !== null && sessions.length === 0 && !sessionsError && (
          <div className="empty">No session rows — unexpected while you are signed in.</div>
        )}
        {sessions !== null && sessions.length > 0 && (
          <table className="tbl">
            <thead>
              <tr><th>Last seen</th><th>From</th><th>Client</th><th>Expires in</th></tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr key={`${s.created_at}-${s.source_ip}`}>
                  <td>{when(s.last_seen_at)}</td>
                  <td>{s.source_ip || '—'}</td>
                  <td title={s.user_agent}>{(s.user_agent || '—').slice(0, 40)}</td>
                  <td>{Math.round((s.expires_in || 0) / 60)} min</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <button className="btn btn--danger btn--sm" type="button" onClick={revokeAll}
                style={{ marginTop: 10 }}>
          Sign out everywhere
        </button>
        <div className="scan-note">
          Ends every session for this account, this one included.
        </div>
      </div>
    </div>
  );
}
