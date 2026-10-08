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
  // Write-only integration tokens typed this session (never read back).
  const [keyIn, setKeyIn] = useState({});

  useEffect(() => {
    // A blank Settings page and a dead backend looked identical.
    api.settings.get().then(setS).catch((e) => { setS(null); setLoadError(e.message); });
  }, []);

  if (!s) return <div className="page">
      <h1 className="sr-only">Settings</h1><div className="card"><div className="card__body"><div className="empty">Loading settings...</div></div></div></div>;

  const safety = s.safety || {};
  const scope = s.scope || {};
  const budget = s.budget || {};
  const setBudget = (k, v) => setS((x) => ({ ...x, budget: { ...(x.budget || {}), [k]: v } }));
  const setSafety = (k, v) => setS((x) => ({ ...x, safety: { ...(x.safety || {}), [k]: v } }));
  const setScope = (k, v) => setS((x) => ({ ...x, scope: { ...(x.scope || {}), [k]: v } }));
  const exploit = s.exploit || {};
  const setExploit = (k, v) => setS((x) => ({ ...x, exploit: { ...(x.exploit || {}), [k]: v } }));

  // The model router and the provider keys are saved by <ModelRouter/>, which
  // owns them on both screens. This button saves everything else.
  // Only send tokens the operator actually typed: a value sets it, the sentinel
  // clears it, an untouched field is omitted (leave unchanged).
  function integrationPatch() {
    const out = {};
    for (const [k, v] of Object.entries(keyIn)) {
      if (v === '__unset__' || (typeof v === 'string' && v.trim())) out[k] = v;
    }
    return out;
  }

  async function save() {
    try {
      const patch = {
        safety: s.safety, scope: s.scope,
        oob_server: s.oob_server || '', budget: s.budget,
        exploit: s.exploit,
      };
      const ik = integrationPatch();
      if (Object.keys(ik).length) patch.integration_keys = ik;
      const res = await api.settings.save(patch);
      setS(res); setKeyIn({}); setSaveError(null); setSaved('Saved');
    } catch (e) { setSaveError(e.message); setSaved(null); }
    setTimeout(() => setSaved(null), 2500);
  }

  const INTG = [
    { k: 'github', label: 'GitHub token', ph: 'github_pat_…  — raises PoC search 10→30/min' },
    { k: 'shodan', label: 'Shodan API key', ph: 'account.shodan.io' },
    { k: 'censys_id', label: 'Censys API ID', ph: 'search.censys.io → API credentials' },
    { k: 'censys_secret', label: 'Censys API secret', ph: '' },
    { k: 'virustotal', label: 'VirusTotal API key', ph: 'virustotal.com → your API key' },
  ];
  const intgStatus = s.integration_keys || {};

  return (
    <div className="page">
      <Notice kind="error" message={loadError} />
      {/* The backend warns when provider keys will not survive a restart.
          Nothing rendered it, so an operator typed API keys into the
          Integrations card and was never told. */}
      <Notice kind="warn" message={s.key_warning} />
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
              <label className="field__label" htmlFor="set-apikey">X-API-Key sent with every request</label>
              <input id="set-apikey" className="input" type="password" placeholder="leave empty — you are signed in with an account"
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
              <label className="field__label" htmlFor="set-monthly">Monthly cap (USD)</label>
              <input id="set-monthly" className="input" type="number" min="0" step="1" value={budget.monthly_usd ?? 0}
                     onChange={(e) => setBudget('monthly_usd', Number(e.target.value))} />
            </div>
            <div className="field">
              <label className="field__label" htmlFor="set-pereng">Per-engagement cap (USD)</label>
              <input id="set-pereng" className="input" type="number" min="0" step="1" value={budget.per_engagement_usd ?? 0}
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
              <div className="field"><label className="field__label" htmlFor="set-rate">Rate (req/s)</label><input id="set-rate" className="input" type="number" value={scope.rate ?? 10} onChange={(e) => setScope('rate', Number(e.target.value))} /></div>
              <div className="field"><label className="field__label" htmlFor="set-conc">Concurrency</label><input id="set-conc" className="input" type="number" value={scope.concurrency ?? 4} onChange={(e) => setScope('concurrency', Number(e.target.value))} /></div>
            </div>
            <div className="field"><label className="field__label" htmlFor="set-oob">OOB / interactsh server <span style={{ textTransform: 'none', color: 'var(--text-faint)', fontWeight: 400 }}>blank = public servers</span></label><input id="set-oob" className="input" placeholder="https://oob.yourdomain.com" value={s.oob_server || ''} onChange={(e) => setS((x) => ({ ...x, oob_server: e.target.value }))} /></div>
          </div>
        </div>

        <div className="card set-full">
          <div className="card__head">
            <span className="card__title">Exploitation</span>
            <span className="card__meta">how a finding gets proven</span>
          </div>
          <div className="card__body">
            <p className="intro">
              A finding only reaches &ldquo;confirmed&rdquo; when something runs against
              the target and returns cleanly. These control how far the tool goes
              on its own. Every run is still scope-enforced and happens inside the
              isolated sandbox.
            </p>
            <div className="toggle-row">
              <span className="toggle-row__txt">
                Run vetted proofs automatically — a PoC that passes both readings
                (safe for the target, no malware aimed at you) runs in the sandbox
                without waiting for a click. Anything suspicious still waits for you.
              </span>
              <Toggle on={exploit.auto_run_poc !== false}
                      onChange={(v) => setExploit('auto_run_poc', v)} />
            </div>
            <div className="field" style={{ marginTop: 12 }}>
              <label className="field__label" htmlFor="set-refine">
                Exploit rehearsal rounds{' '}
                <span style={{ textTransform: 'none', color: 'var(--text-faint)', fontWeight: 400 }}>
                  0 = the model writes it blind and never sees it run
                </span>
              </label>
              <input id="set-refine" className="input" type="number" min={0} max={10}
                     value={exploit.refine_iterations ?? 2}
                     onChange={(e) => setExploit('refine_iterations', Number(e.target.value))} />
              <p className="poc-note" style={{ marginTop: 6 }}>
                Published exploits are often only a checker: they print
                &ldquo;vulnerable&rdquo; and exit, which proves nothing. When that
                happens the model writes an exploit for this exact finding, watches
                it run in the sandbox and fixes it, up to this many rounds.
              </p>
            </div>
          </div>
        </div>

        <div className="card set-full">
          <div className="card__head">
            <span className="card__title">Integrations &amp; API keys</span>
            <span className="card__meta">stored encrypted · write-only</span>
          </div>
          <div className="card__body">
            <p className="intro">
              Threat-intel and PoC-search tokens. Set them here instead of the
              .env file; they are encrypted at rest and never shown back. All are
              optional and free to obtain.
            </p>
            {INTG.map(({ k, label, ph }) => {
              const isSet = intgStatus[k] === 'set';
              const typed = keyIn[k];
              return (
                <div className="field" key={k}>
                  <label className="field__label" htmlFor={'intg-' + k}>
                    {label}{' '}
                    <span style={{ textTransform: 'none', fontWeight: 400,
                                   color: isSet ? 'var(--brand)' : 'var(--text-faint)' }}>
                      {typed === '__unset__' ? 'will clear on save' : isSet ? 'set' : 'not set'}
                    </span>
                  </label>
                  <div className="key-row">
                    <input id={'intg-' + k} className="input" type="password"
                           autoComplete="new-password"
                           placeholder={isSet ? '•••••••• (leave blank to keep)' : ph}
                           value={typed && typed !== '__unset__' ? typed : ''}
                           onChange={(e) => setKeyIn((x) => ({ ...x, [k]: e.target.value }))} />
                    {isSet && (
                      <button type="button" className="btn btn--muted btn--sm"
                              onClick={() => setKeyIn((x) => ({ ...x, [k]: x[k] === '__unset__' ? '' : '__unset__' }))}>
                        {typed === '__unset__' ? 'keep' : 'clear'}
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
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
