import { useEffect, useState } from 'react';
import { api, getApiKey, setApiKey } from '../lib/api.js';
import { Notice } from '../components/ui.jsx';
import KnowledgeMap from '../components/KnowledgeMap.jsx';
import AccountCard from '../components/AccountCard.jsx';
import ModelRouter from '../components/ModelRouter.jsx';
import OperatorsCard from '../components/OperatorsCard.jsx';

function Toggle({ on, onChange }) {
  return (
    <button type="button" className={'toggle' + (on ? ' toggle--on' : '')} onClick={() => onChange(!on)} aria-pressed={on}>
      <span className="toggle__track"></span>
      <span className="toggle__knob"></span>
    </button>
  );
}

export default function Settings() {
  const [loadError, setLoadError] = useState(null);
  const [s, setS] = useState(null);
  const [saved, setSaved] = useState(null);
  const [saveError, setSaveError] = useState(null);
  const [apiKeyInput, setApiKeyInput] = useState(getApiKey());
  const apiKey = apiKeyInput;

  useEffect(() => {
    // A blank Settings page and a dead backend looked identical.
    api.settings.get().then(setS).catch((e) => { setS(null); setLoadError(e.message); });
  }, []);

  if (!s) return <div className="page"><div className="card"><div className="card__body"><div className="empty">Loading settings...</div></div></div></div>;

  const safety = s.safety || {};
  const scope = s.scope || {};
  const budget = s.budget || {};
  const setBudget = (k, v) => setS((x) => ({ ...x, budget: { ...(x.budget || {}), [k]: v } }));
  const setSafety = (k, v) => setS((x) => ({ ...x, safety: { ...(x.safety || {}), [k]: v } }));
  const setScope = (k, v) => setS((x) => ({ ...x, scope: { ...(x.scope || {}), [k]: v } }));

  // The model router and the provider keys are saved by <ModelRouter/>, which
  // owns them on both screens. This button saves everything else.
  async function save() {
    try {
      const res = await api.settings.save({
        safety: s.safety, scope: s.scope,
        oob_server: s.oob_server || '', budget: s.budget,
      });
      setS(res); setSaveError(null); setSaved('Saved');
    } catch (e) { setSaveError(e.message); setSaved(null); }
    setTimeout(() => setSaved(null), 2500);
  }

  return (
    <div className="page">
      <Notice kind="error" message={loadError} />
      <div style={{ marginBottom: 16 }}>
        <KnowledgeMap categories={[]} confidence={s.llm?.ready ? 100 : 0}
                      title="Settings"
                      subtitle={s.llm?.ready ? 'model router ready' : (s.llm?.summary || 'model router not configured')}
                      metricLabel="router"
                      idleNote="Configuration — safety, budget, scope and the model router. No run data to map here." />
      </div>
      <div className="set-grid">
        <AccountCard />

        <OperatorsCard />

        <div className="card set-full">
          <div className="card__head"><span className="card__title">Machine credential</span><span className="card__meta">this browser only &middot; never sent to the server settings</span></div>
          <div className="card__body">
            <div className="field">
              <label className="field__label">X-API-Key sent with every request</label>
              <input className="input" type="password" placeholder="leave empty — you are signed in with an account"
                     value={apiKey} onChange={(e) => setApiKeyInput(e.target.value)} />
            </div>
            <div className="scan-note">
              You are already authenticated by your session; this is only needed
              when driving the API from a script or CI, and it must match the
              backend&apos;s SYPHAX_API_KEY. Stored in this browser&apos;s
              localStorage, not in the server settings.
            </div>
            <button className="btn btn--muted" onClick={() => { setApiKey(apiKeyInput); setSaved('API key saved in this browser'); setTimeout(() => setSaved(null), 2500); }}>Save API key</button>
          </div>
        </div>

        <div className="card set-full">
          <div className="card__head">
            <span className="card__title">Model router</span>
            <span className={'card__meta ' + (s.llm?.ready ? '' : 'card__meta--warn')}>
              {s.llm?.ready ? 'all three roles configured' : (s.llm?.summary || 'not configured')}
            </span>
          </div>
          <div className="card__body">
            {/* Same component as the first-run screen. Two copies of this form
                would drift, and the one that drifted would be the one an
                operator used to fix a broken install. */}
            <ModelRouter />
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

      <Notice kind="error" title="Could not save settings" message={saveError} onRetry={() => setSaveError(null)} />
      <div className="set-actions">
        <button className="btn btn--solid" onClick={save}>Save settings</button>
        {saved && <span className="set-actions__msg">{saved}</span>}
      </div>
    </div>
  );
}
