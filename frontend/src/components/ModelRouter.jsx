import { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../lib/api.js';
import { Notice } from './ui.jsx';

/**
 * Pick a provider and a model for each of the three roles, and store the keys.
 *
 * One component, two placements: the first-run screen that the tool will not
 * start without, and the Settings card that changes it later. Two copies of
 * this form would drift, and the one that drifted would be the one an operator
 * used to fix a broken install.
 *
 * The catalog comes from the backend (/api/llm/providers) rather than being
 * hardcoded here, so the base URL a role is given is the exact string the
 * backend matches against when it decides which stored key to use.
 */

const ROLE_ORDER = ['planner', 'executor', 'validator'];

function blankKeys(providers) {
  return Object.fromEntries(providers.map((p) => [p.id, '']));
}

export default function ModelRouter({ onSaved, compact = false }) {
  const [catalog, setCatalog] = useState(null);
  const [roleMeta, setRoleMeta] = useState([]);
  const [settings, setSettings] = useState(null);
  const [keys, setKeys] = useState({});
  const [sameForAll, setSameForAll] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [saved, setSaved] = useState('');
  const [pings, setPings] = useState({});

  const load = useCallback(async () => {
    setError('');
    try {
      const [prov, s] = await Promise.all([api.llm.providers(), api.settings.get()]);
      const items = prov?.items || [];
      setCatalog(items);
      setRoleMeta(prov?.roles || []);
      setSettings(s);
      setKeys(blankKeys(items));
      // Start on the simple path only when nothing is configured yet or the
      // three roles already agree; an operator who deliberately split them
      // must not have that silently collapsed on their next save.
      const urls = ROLE_ORDER.map((r) => s?.model_router?.[r]?.base_url || '');
      setSameForAll(new Set(urls).size <= 1);
    } catch (e) {
      setError(e.message);
      setCatalog([]);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const byId = useMemo(
    () => Object.fromEntries((catalog || []).map((p) => [p.id, p])),
    [catalog]);

  const providerOf = useCallback((role) => {
    const url = settings?.model_router?.[role]?.base_url || '';
    if (!url) return '';
    const hit = (catalog || []).find((p) => p.base_url && url.startsWith(p.base_url));
    return hit ? hit.id : 'custom';
  }, [catalog, settings]);

  function setRole(role, patch) {
    setSettings((s) => ({
      ...s,
      model_router: {
        ...(s?.model_router || {}),
        [role]: { ...(s?.model_router?.[role] || {}), ...patch },
      },
    }));
  }

  function chooseProvider(role, providerId) {
    const p = byId[providerId];
    const roles = sameForAll ? ROLE_ORDER : [role];
    roles.forEach((r) => setRole(r, {
      base_url: p ? p.base_url : '',
      model: p && p.models.length ? p.models[0] : '',
    }));
  }

  function chooseModel(role, model) {
    (sameForAll ? ROLE_ORDER : [role]).forEach((r) => setRole(r, { model }));
  }

  // Every provider a role currently points at needs a key: one stored already,
  // or one typed into this form.
  const needed = useMemo(() => {
    const ids = new Set(ROLE_ORDER.map(providerOf).filter(Boolean));
    return [...ids];
  }, [providerOf]);

  const missingKeys = needed.filter(
    (id) => settings?.provider_keys?.[id] !== 'set' && !(keys[id] || '').trim());

  async function save() {
    setBusy(true); setError(''); setSaved('');
    const provider_keys = {};
    Object.entries(keys).forEach(([id, v]) => { if (v.trim()) provider_keys[id] = v.trim(); });
    try {
      const res = await api.settings.save({
        model_router: settings.model_router,
        provider_keys: Object.keys(provider_keys).length ? provider_keys : undefined,
      });
      setSettings(res);
      setKeys(blankKeys(catalog || []));
      setSaved('Saved.');
      if (res?.llm?.ready && onSaved) onSaved(res);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function ping(role) {
    const provider = providerOf(role);
    const cfg = settings?.model_router?.[role] || {};
    const typedKey = (keys[provider] || '').trim();
    const savedKey = settings?.provider_keys?.[provider] === 'set';
    // Honest, not misleading: with no key at all the saved config silently
    // falls back to OpenRouter (qwen) and would report a green success for the
    // wrong model. Say what is actually missing instead.
    if (!typedKey && !savedKey) {
      setPings((p) => ({ ...p, [role]: { state: 'fail',
        text: `no API key for ${provider || 'this provider'} — paste it in API Keys below, then test` } }));
      return;
    }
    setPings((p) => ({ ...p, [role]: { state: 'running' } }));
    try {
      // A key typed here (not yet saved) tests the exact form values now;
      // otherwise the saved role config is pinged.
      const override = typedKey
        ? { base_url: cfg.base_url, model: cfg.model, api_key: typedKey }
        : undefined;
      const r = await api.llmPing(role, override);
      if (r.fallback_used) {
        setPings((p) => ({ ...p, [role]: { state: 'warn',
          text: `no usable key for ${provider} — fell back to ${r.model_used}. Add the key and Save.` } }));
      } else {
        setPings((p) => ({ ...p, [role]: { state: 'ok', text: `${r.model_used} · ${r.latency_ms} ms` } }));
      }
    } catch (e) {
      setPings((p) => ({ ...p, [role]: { state: 'fail', text: e.message } }));
    }
  }

  if (catalog === null) return <div className="empty empty--loading">Loading providers…</div>;
  if (!settings) return <Notice kind="error" message={error || 'Settings unavailable.'} onRetry={load} />;

  const ready = settings.llm?.ready;
  const visibleRoles = sameForAll ? ['planner'] : ROLE_ORDER;

  return (
    <div className="mr">
      <Notice kind="error" message={error} />
      {saved && <Notice kind="info" message={saved} />}

      {!ready && settings.llm?.summary && (
        <Notice kind="warn" title="Not configured" message={settings.llm.summary} />
      )}

      <label className="mr__same">
        <input type="checkbox" checked={sameForAll}
               onChange={(e) => setSameForAll(e.target.checked)} />
        <span>
          One provider for all three roles
          <small>
            Uncheck to split them. The usual split is a strong model on the
            planner, where the decisions are made, and a cheap fast one on the
            executor, which runs constantly.
          </small>
        </span>
      </label>

      {visibleRoles.map((role) => {
        const cfg = settings.model_router?.[role] || {};
        const pid = providerOf(role);
        const provider = byId[pid];
        const meta = roleMeta.find((m) => m.role === role);
        const p = pings[role];
        return (
          <div key={role} className="mr__role">
            <div className="mr__head">
              <span className="mr__name">{sameForAll ? 'All roles' : role}</span>
              {!sameForAll && meta?.note && <small className="mr__note">{meta.note}</small>}
            </div>

            <div className="field">
              <label className="field__label" htmlFor={`prov-${role}`}>Provider</label>
              <div className="select-box">
                <select id={`prov-${role}`} className="select" value={pid}
                        onChange={(e) => chooseProvider(role, e.target.value)}>
                  <option value="">— choose a provider —</option>
                  {catalog.map((p2) => (
                    <option key={p2.id} value={p2.id}>{p2.label}</option>
                  ))}
                </select>
              </div>
              {provider?.note && <span className="field__hint">{provider.note}</span>}
            </div>

            <div className="router-row">
              <div className="router-row__role">endpoint<small>base URL</small></div>
              <input className="input" placeholder="https://…" value={cfg.base_url || ''}
                     onChange={(e) => setRole(role, { base_url: e.target.value })} />
              <input className="input" placeholder="model" list={`models-${role}`}
                     value={cfg.model || ''}
                     onChange={(e) => chooseModel(role, e.target.value)} />
              <datalist id={`models-${role}`}>
                {(provider?.models || []).map((m) => <option key={m} value={m} />)}
              </datalist>
            </div>

            {!compact && (
              <div className="mr__ping">
                <button type="button" className="btn btn--muted btn--sm"
                        onClick={() => ping(role)}
                        disabled={p?.state === 'running'}>
                  {p?.state === 'running' ? 'Testing…' : 'Test this role'}
                </button>
                {p?.state === 'ok' && <span className="key-status ok">{p.text}</span>}
                {p?.state === 'warn' && <span className="key-status" style={{ color: 'var(--sev-high)' }}>{p.text}</span>}
                {p?.state === 'fail' && <span className="key-status" style={{ color: 'var(--sev-critical)' }}>{p.text}</span>}
              </div>
            )}
          </div>
        );
      })}

      <div className="io-label">API keys</div>
      {needed.length === 0 && (
        <div className="empty">Choose a provider first.</div>
      )}
      {needed.map((id) => {
        const stored = settings.provider_keys?.[id] === 'set';
        const provider = byId[id];
        return (
          <div key={id} className="field">
            <label className="field__label" htmlFor={`key-${id}`}>
              {provider?.label || id}{' '}
              <span className={'key-status ' + (stored ? 'ok' : 'unset')}>
                {stored ? 'set' : 'required'}
              </span>
            </label>
            <input id={`key-${id}`} className="input" type="password"
                   placeholder={stored ? '•••••••• (leave blank to keep)' : 'paste the API key'}
                   value={keys[id] || ''}
                   onChange={(e) => setKeys((k) => ({ ...k, [id]: e.target.value }))} />
            {provider?.console_url && (
              <span className="field__hint">
                Keys: <a href={provider.console_url} target="_blank" rel="noreferrer">
                  {provider.console_url}
                </a>
              </span>
            )}
          </div>
        );
      })}

      <div className="scan-note">
        Keys are encrypted before they are written and are never sent back to
        this page — it can only report whether one is stored.
      </div>

      <button className="btn btn--solid" type="button" onClick={save}
              disabled={busy || missingKeys.length > 0 || needed.length === 0}>
        {busy ? 'Saving…' : 'Save model router'}
      </button>
      {missingKeys.length > 0 && (
        <span className="field__hint" style={{ marginLeft: 10 }}>
          Missing a key for: {missingKeys.join(', ')}
        </span>
      )}
    </div>
  );
}
