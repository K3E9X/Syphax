import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api.js';
import { useAuth } from '../lib/auth.jsx';
import { Empty, Notice } from './ui.jsx';

/**
 * The other accounts on this install.
 *
 * A VM shared by two or three testers is the case this exists for. Each of
 * them gets their own password and their own line in the audit log, which is
 * the point: "who ran this scan" is not a question a shared account can answer.
 *
 * Admin only, and the check is on the server - this component just avoids
 * rendering a form that would 403.
 */
const ROLES = [
  ['operator', 'Runs engagements. Cannot add or remove accounts.'],
  ['admin', 'Everything, including this panel.'],
];

function when(ts) {
  return ts ? new Date(ts * 1000).toLocaleDateString() : 'never';
}

export default function OperatorsCard() {
  const { user } = useAuth();
  const [items, setItems] = useState(null);
  const [error, setError] = useState('');
  const [form, setForm] = useState({ username: '', password: '', role: 'operator' });
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState(null);

  const load = useCallback(() => api.auth.users()
    .then((r) => { setItems(r?.items || []); setError(''); })
    .catch((e) => { setItems([]); setError(e.message); }), []);

  useEffect(() => { if (user?.role === 'admin') load(); }, [user, load]);

  if (user?.role !== 'admin') return null;

  async function add(e) {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError('');
    try {
      await api.auth.addUser(form);
      setForm({ username: '', password: '', role: 'operator' });
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function remove(id) {
    setError('');
    try {
      await api.auth.removeUser(id);
      setConfirming(null);
      await load();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="card set-full">
      <div className="card__head">
        <span className="card__title">Operators</span>
        <span className="card__meta">
          {items ? `${items.length} account${items.length === 1 ? '' : 's'}` : ''}
        </span>
      </div>
      <div className="card__body">
        <Notice kind="error" message={error} onRetry={load} />

        {items === null && <div className="empty empty--loading">Loading…</div>}
        {items?.length === 0 && !error && <Empty>No accounts — which cannot be true.</Empty>}

        {!!items?.length && (
          <table className="tbl">
            <thead>
              <tr><th>Username</th><th>Role</th><th>Created</th><th>Last sign-in</th><th /></tr>
            </thead>
            <tbody>
              {items.map((u) => (
                <tr key={u.id}>
                  <td className="mono">
                    {u.username}
                    {u.id === user.id && <span className="ops__you"> you</span>}
                  </td>
                  <td>{u.role}</td>
                  <td>{when(u.created_at)}</td>
                  <td>{when(u.last_login_at)}</td>
                  <td style={{ textAlign: 'right' }}>
                    {u.id !== user.id && (
                      confirming === u.id ? (
                        <>
                          <button type="button" className="btn btn--danger btn--sm"
                                  onClick={() => remove(u.id)}>
                            Delete {u.username}
                          </button>{' '}
                          <button type="button" className="btn btn--muted btn--sm"
                                  onClick={() => setConfirming(null)}>Cancel</button>
                        </>
                      ) : (
                        <button type="button" className="btn btn--muted btn--sm"
                                onClick={() => setConfirming(u.id)}>Remove</button>
                      )
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div className="io-label">Add an operator</div>
        <form className="ops__add" onSubmit={add}>
          <div className="field">
            <label className="field__label" htmlFor="ops-user">Username</label>
            <input id="ops-user" className="input" autoCapitalize="none" spellCheck="false"
                   value={form.username}
                   onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))} />
          </div>
          <div className="field">
            <label className="field__label" htmlFor="ops-pass">Initial password</label>
            <input id="ops-pass" className="input" type="password" autoComplete="new-password"
                   value={form.password}
                   onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))} />
            <span className="field__hint">
              At least 12 characters. They can change it under Account; there is no
              reset link, so give it to them over something you trust.
            </span>
          </div>
          <div className="field">
            <label className="field__label" htmlFor="ops-role">Role</label>
            <div className="select-box">
              <select id="ops-role" className="select" value={form.role}
                      onChange={(e) => setForm((f) => ({ ...f, role: e.target.value }))}>
                {ROLES.map(([value, note]) => (
                  <option key={value} value={value}>{value} — {note}</option>
                ))}
              </select>
            </div>
          </div>
          <button className="btn" type="submit"
                  disabled={busy || !form.username.trim() || !form.password}>
            {busy ? 'Working…' : 'Add operator'}
          </button>
        </form>
      </div>
    </div>
  );
}
