import { useEffect, useState } from 'react';
import { api, getApiKey, setApiKey } from '../lib/api.js';

function Toggle({ on, onChange }) {
  return (
    <button type="button" className={'toggle' + (on ? ' toggle--on' : '')} onClick={() => onChange(!on)} aria-pressed={on}>
      <span className="toggle__track"></span>
      <span className="toggle__knob"></span>
    </button>
  );
}

const ROLES = ['planner', 'executor', 'validator'];
const PROVIDERS = [['zai', 'Z.ai (GLM)'], ['moonshot', 'Moonshot (Kimi)'], ['openrouter', 'OpenRouter']];

export default function Settings() {
  const [s, setS] = useState(null);
  const [keyInput, setKeyInput] = useState({ zai: '', moonshot: '', openrouter: '' });
  const [saved, setSaved] = useState(null);
  const [apiKeyInput, setApiKeyInput] = useState(getApiKey());
  const apiKey = apiKeyInput;

  useEffect(() => { api.settings.get().then(setS).catch(() => setS(null)); }, []);

  if (!s) return <div className="page"><div className="card"><div className="card__body"><div className="empty">Loading settings...</div></div></div></div>;

  const mr = s.model_router || {};
  const safety = s.safety || {};
  const scope = s.scope || {};
  const pk = s.provider_keys || {};
  const budget = s.budget || {};
  const setBudget = (k, v) => setS((x) => ({ ...x, budget: { ...(x.budget || {}), [k]: v } }));
  const setRole = (role, patch) => setS((x) => ({ ...x, model_router: { ...x.model_router, [role]: { ...(x.model_router?.[role] || {}), ...patch } } }));
  const setSafety = (k, v) => setS((x) => ({ ...x, safety: { ...(x.safety || {}), [k]: v } }));
  const setScope = (k, v) => setS((x) => ({ ...x, scope: { ...(x.scope || {}), [k]: v } }));

  async function save() {
    const provider_keys = {};
    for (const [p] of PROVIDERS) if (keyInput[p].trim()) provider_keys[p] = keyInput[p].trim();
    try {
      const res = await api.settings.save({
        model_router: s.model_router, safety: s.safety, scope: s.scope,
        oob_server: s.oob_server || '', budget: s.budget,
        provider_keys: Object.keys(provider_keys).length ? provider_keys : undefined,
      });
      setS(res); setKeyInput({ zai: '', moonshot: '', openrouter: '' }); setSaved('Saved');
    } catch (e) { setSaved('Error: ' + e.message); }
    setTimeout(() => setSaved(null), 2500);
  }

  return (
    <div className="page">
      <div className="set-grid">
        <div className="card set-full">
          <div className="card__head"><span className="card__title">API key</span><span className="card__meta">this browser only &middot; never sent to the server settings</span></div>
          <div className="card__body">
            <div className="field">
              <label className="field__label">X-API-Key sent with every request</label>
              <input className="input" type="password" placeholder="leave empty if the backend runs unauthenticated"
                     value={apiKey} onChange={(e) => setApiKeyInput(e.target.value)} />
            </div>
            <div className="scan-note">
              Required only when the backend sets SYPHAX_API_KEY. Stored in this
              browser&apos;s localStorage, not in the server settings.
            </div>
            <button className="btn btn--muted" onClick={() => { setApiKey(apiKeyInput); setSaved('API key saved in this browser'); setTimeout(() => setSaved(null), 2500); }}>Save API key</button>
          </div>
        </div>

        <div className="card set-full">
          <div className="card__head"><span className="card__title">Model router</span><span className="card__meta">per-role endpoint + model</span></div>
          <div className="card__body">
            {ROLES.map((role) => (
              <div key={role} className="router-row">
                <div className="router-row__role">{role}<small>role</small></div>
                <input className="input" placeholder="base URL (e.g. https://api.z.ai/api/paas/v4)" value={mr[role]?.base_url || ''} onChange={(e) => setRole(role, { base_url: e.target.value })} />
                <input className="input" placeholder="model (e.g. glm-4.6)" value={mr[role]?.model || ''} onChange={(e) => setRole(role, { model: e.target.value })} />
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card__head"><span className="card__title">Provider keys</span><span className="card__meta">write-only &middot; never returned</span></div>
          <div className="card__body">
            {PROVIDERS.map(([p, label]) => (
              <div key={p} className="field">
                <label className="field__label">{label} <span className={'key-status ' + (pk[p] === 'set' ? 'ok' : 'unset')}>{pk[p] === 'set' ? 'set' : 'unset'}</span></label>
                <div className="key-row">
                  <input className="input" type="password" placeholder={pk[p] === 'set' ? '•••••••• (leave blank to keep)' : 'paste key to set'} value={keyInput[p]} onChange={(e) => setKeyInput((k) => ({ ...k, [p]: e.target.value }))} />
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card__head"><span className="card__title">Safety</span></div>
          <div className="card__body">
            <div className="toggle-row"><span className="toggle-row__txt">Safe-PoC only (read-only proofs)</span><Toggle on={safety.safe_mode !== false} onChange={(v) => setSafety('safe_mode', v)} /></div>
            <div className="toggle-row"><span className="toggle-row__txt">Require approval before exploitation</span><Toggle on={!!safety.require_approval} onChange={(v) => setSafety('require_approval', v)} /></div>
            <div className="toggle-row"><span className="toggle-row__txt">Auto-validate findings</span><Toggle on={safety.auto_validate !== false} onChange={(v) => setSafety('auto_validate', v)} /></div>
            <div className="toggle-row"><span className="toggle-row__txt">Out-of-band (interactsh) enabled</span><Toggle on={!!safety.oob_enabled} onChange={(v) => setSafety('oob_enabled', v)} /></div>
          </div>
        </div>

        <div className="card">
          <div className="card__head"><span className="card__title">LLM budget</span><span className="card__meta">0 = no limit</span></div>
          <div className="card__body">
            <div className="field">
              <label className="field__label">Monthly cap (USD)</label>
              <input className="input" type="number" min="0" step="1" value={budget.monthly_usd ?? 0}
                     onChange={(e) => setBudget('monthly_usd', Number(e.target.value))} />
            </div>
            <div className="field">
              <label className="field__label">Per-engagement cap (USD)</label>
              <input className="input" type="number" min="0" step="1" value={budget.per_engagement_usd ?? 0}
                     onChange={(e) => setBudget('per_engagement_usd', Number(e.target.value))} />
            </div>
            <p className="home-intro">
              Needs LLM_PRICING set in .env. Without it every model is costed at $0
              and the cap can never trigger.
            </p>
          </div>
        </div>

        <div className="card set-full">
          <div className="card__head"><span className="card__title">Scope &amp; out-of-band</span></div>
          <div className="card__body">
            <div className="router-row">
              <div className="router-row__role">limits</div>
              <div className="field"><label className="field__label">Rate (req/s)</label><input className="input" type="number" value={scope.rate ?? 10} onChange={(e) => setScope('rate', Number(e.target.value))} /></div>
              <div className="field"><label className="field__label">Concurrency</label><input className="input" type="number" value={scope.concurrency ?? 4} onChange={(e) => setScope('concurrency', Number(e.target.value))} /></div>
            </div>
            <div className="field"><label className="field__label">OOB / interactsh server <span style={{ textTransform: 'none', color: 'var(--text-faint)', fontWeight: 400 }}>blank = public servers</span></label><input className="input" placeholder="https://oob.yourdomain.com" value={s.oob_server || ''} onChange={(e) => setS((x) => ({ ...x, oob_server: e.target.value }))} /></div>
          </div>
        </div>
      </div>

      <div className="form-actions" style={{ marginTop: 6 }}>
        <button className="btn btn--solid" onClick={save}>Save settings</button>
        {saved && <span className="form-error" style={{ color: 'var(--text-secondary)' }}>{saved}</span>}
      </div>
    </div>
  );
}
