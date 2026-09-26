import { useCallback, useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { api } from '../lib/api.js';
import { COV_AXES, Radar } from '../components/Charts.jsx';
import { Notice, activateOnKey } from '../components/ui.jsx';
import KnowledgeMap from '../components/KnowledgeMap.jsx';
import { mapFromEngagements } from '../lib/knowledgeMap.js';

/* custom checkbox - square + CSS check, no icon */
function Check({ checked, onChange, children, className = '' }) {
  return (
    <label className={'check ' + className}>
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span className={'check__box' + (checked ? ' check__box--on' : '')}></span>
      <span className="check__txt">{children}</span>
    </label>
  );
}

function SevMini({ sev }) {
  const map = [['critical', 'var(--severity-critical)'], ['high', 'var(--severity-high)'], ['medium', 'var(--severity-medium)'], ['low', 'var(--severity-low)']];
  const tot = (sev.critical || 0) + (sev.high || 0) + (sev.medium || 0) + (sev.low || 0);
  if (!tot) return <span style={{ color: 'var(--text-faint)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>-</span>;
  return <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, display: 'inline-flex', gap: 8 }}>{map.filter(([k]) => sev[k]).map(([k, col]) => <span key={k} style={{ color: col }}>{sev[k]}{k[0].toUpperCase()}</span>)}</span>;
}

const BLANK = {
  target_url: '', scope_hosts: '', auth: '', secondary_auth: '',
  require_approval: false, allow_active_exploit: false,
  allow_sql_os_cmd: false, allow_data_proof: false, attest: false,
  // Empty means "follow USER_AGENT_MODE from the environment", which is what
  // every engagement created before this field existed does.
  user_agent_mode: '', user_agent: '',
  // Beyond read-only proof. Empty is the default and is right for most
  // engagements.
  exploit_capabilities: [],
};

export default function Engagements() {
  const nav = useNavigate();
  // Pre-recon hands the target over in router state rather than a query
  // string: the scope list it suggests can be two hundred hostnames, and a URL
  // is the wrong place for them.
  const handoff = useLocation().state || {};
  const [form, setForm] = useState(
    handoff.target_url
      ? { ...BLANK, target_url: handoff.target_url, scope_hosts: handoff.scope_hosts || '' }
      : BLANK);
  const [items, setItems] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [toast, setToast] = useState(null);
  const [error, setError] = useState(null);
  const [identities, setIdentities] = useState(null);
  const [caps, setCaps] = useState(null);
  const set = (patch) => setForm((f) => ({ ...f, ...patch }));

  useEffect(() => {
    // A failure here costs the picker and nothing else - the field falls back
    // to "follow the environment", which is the old behaviour. It still has to
    // be visible, or the select silently disappears.
    api.scans.identities()
      .then(setIdentities)
      .catch((e) => setError((prev) => prev || `Could not load the identity list: ${e.message}`));
    // Without this the capability section renders empty and the operator
    // silently gets read-only proof while believing they authorized more.
    api.engagements.capabilities()
      .then(setCaps)
      .catch((e) => setError((prev) => prev || `Could not load the capability list: ${e.message}`));
  }, []);

  const load = useCallback(async () => {
    try { const r = await api.engagements.list(); setItems(r.items || []); }
    catch (e) { setError(e.message); }
  }, []);
  useEffect(() => { load(); }, [load]);

  async function onCreate(e) {
    e.preventDefault();
    setError(null);
    if (!form.target_url) { setError('Target URL is required.'); return; }
    if (!form.attest) { setError('You must attest you are authorized to test this target.'); return; }
    const scope = form.scope_hosts.split(',').map((s) => s.trim()).filter(Boolean);
    try {
      const res = await api.engagements.create({
        target_url: form.target_url,
        scope_hosts: scope.length ? scope : undefined,
        exploit_capabilities: form.exploit_capabilities.length
          ? form.exploit_capabilities : undefined,
        user_agent_mode: form.user_agent_mode || undefined,
        user_agent: form.user_agent_mode === 'custom' ? form.user_agent : undefined,
        attest_authorized: true,
        require_exploit_approval: form.require_approval,
        allow_active_exploit: form.allow_active_exploit,
        allow_sql_os_cmd: form.allow_active_exploit && form.allow_sql_os_cmd,
        allow_data_proof: form.allow_active_exploit && form.allow_data_proof,
        auth_headers: form.auth || undefined,
        secondary_auth_headers: form.secondary_auth || undefined,
      });
      setForm(BLANK);
      await load();
      if (res?.engagement?.id) setSelectedId(res.engagement.id);
    } catch (err) { setError(err.message); }
  }

  useEffect(() => {
    if (!toast) return undefined;
    const t = setTimeout(() => setToast(null), 6000);
    return () => clearTimeout(t);
  }, [toast]);

  async function closeEng(id) {
    try { await api.engagements.close(id); await load(); } catch (e) { setError(e.message); }
  }

  // Close only flips a status: the findings stay and every aggregate view
  // keeps mixing them with the next target's. Delete removes them. Confirmed
  // by typing the host, because it cannot be undone - the audit trail and the
  // cross-engagement memory are what survive.
  const [deleting, setDeleting] = useState(null);   // engagement pending confirmation
  const [confirmText, setConfirmText] = useState('');

  async function deleteEng(e) {
    try {
      const r = await api.engagements.remove(e.id);
      const rows = Object.entries(r.rows || {})
        .filter(([, n]) => n > 0)
        .map(([t, n]) => `${n} ${t}`)
        .join(', ');
      setDeleting(null);
      setConfirmText('');
      if (selectedId === e.id) setSelectedId(null);
      await load();
      setError(null);
      setToast(`Deleted ${e.target_host || e.id}${rows ? ` - removed ${rows}` : ''}`);
    } catch (err) {
      setError(err.message);
    }
  }

  const selected = items.find((x) => x.id === selectedId);
  const radarOf = (e) => e.radar || [0, 0, 0, 0, 0, 0];
  const sevOf = (e) => e.severity_counts || {};

  // Fleet knowledge map (shared derivation, also used by Home). Clicking a card
  // opens that engagement in the inspector below.
  const { categories: kmCats, confidence: kmConfidence } = mapFromEngagements(items);

  return (
    <div className="page">
      <h1 className="sr-only">Engagements</h1>
      <Notice kind="error" message={error} onRetry={() => setError(null)} />
      {kmCats.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <KnowledgeMap categories={kmCats} confidence={kmConfidence}
                        title="Engagements map"
                        subtitle={`${items.length} engagement(s) · avg coverage ${kmConfidence}% · click to inspect`}
                        metricLabel="coverage"
                        activeKey={selectedId}
                        onSelect={setSelectedId} />
        </div>
      )}

      <div className="card">
        <div className="card__head"><span className="card__title">New engagement</span></div>
        <div className="card__body">
          <p className="intro">Enter a target you own, attest authorization, and create. The engagement is authorized immediately. Open its live view to run the autonomous test. The scope list limits what will be touched.</p>
          <form className="form" onSubmit={onCreate}>
            <div className="field-grid">
              <div className="field">
                <label className="field__label">Target URL</label>
                <input className="input" placeholder="https://app.example.com" value={form.target_url} onChange={(e) => set({ target_url: e.target.value })} />
              </div>
              <div className="field">
                <label className="field__label">In-scope hosts <span style={{ textTransform: 'none', color: 'var(--text-faint)', fontWeight: 400 }}>optional</span></label>
                <input className="input" placeholder="api.example.com, .example.com" value={form.scope_hosts} onChange={(e) => set({ scope_hosts: e.target.value })} />
                {handoff.from_prerecon && (
                  <span className="field__hint">
                    Prefilled from pre-recon on {handoff.from_prerecon}: names found on the
                    certificate and in Certificate Transparency. These are
                    suggestions — keep only what you are authorized to test.
                  </span>
                )}
                <span className="field__hint">Comma-separated. Prefix with <code>.</code> to allow subdomains.</span>
              </div>
            </div>

            <div className="form-sub">Authenticated testing</div>
            <div className="field">
              <label className="field__label">Primary identity headers <span style={{ textTransform: 'none', color: 'var(--text-faint)', fontWeight: 400 }}>optional</span></label>
              <textarea className="textarea" placeholder="Cookie: session=AAAAA..." value={form.auth} onChange={(e) => set({ auth: e.target.value })}></textarea>
              <span className="field__hint">One per line (e.g. <code>Cookie: session=...</code> or <code>Authorization: Bearer ...</code>). Injected into every scanner so they test behind the login.</span>
            </div>
            <div className="field">
              <label className="field__label">Grey-box: second identity <span style={{ textTransform: 'none', color: 'var(--text-faint)', fontWeight: 400 }}>optional</span></label>
              <textarea className="textarea" placeholder="Cookie: session=BBBBB..." value={form.secondary_auth} onChange={(e) => set({ secondary_auth: e.target.value })}></textarea>
              <span className="field__hint">A second identity's headers. Enables true IDOR/BOLA proof by replaying a captured request as another user.</span>
            </div>

            <div className="form-sub">What the client authorized</div>
            <p className="field__hint" style={{ marginTop: -4, marginBottom: 10 }}>
              {caps?.note
                || 'Leaving these off means read-only proof, which is right for most engagements.'}
            </p>
            <div className="checks">
              {(caps?.items || []).map((c) => {
                const on = form.exploit_capabilities.includes(c.id);
                return (
                  <Check
                    key={c.id}
                    checked={on}
                    onChange={(v) => set({
                      exploit_capabilities: v
                        ? [...form.exploit_capabilities, c.id]
                        : form.exploit_capabilities.filter((x) => x !== c.id),
                    })}
                  >
                    <b>{c.label}:</b> {c.unlocks}.
                    {/* The cost is next to the checkbox on purpose. A box
                        labelled "destructive" with no consequences written
                        beside it is a box that gets ticked. */}
                    <small className="cap-cost">Cost if the client did not sign for it: {c.cost}.</small>
                    <small className="cap-proves">Makes provable: {c.proves}.</small>
                  </Check>
                );
              })}
              {!caps && <span className="field__hint">Loading…</span>}
            </div>
            {caps?.never_grantable && (
              <p className="field__hint">Never grantable: {caps.never_grantable}</p>
            )}

            <div className="form-sub">Scan identity</div>
            <div className="field">
              <label className="field__label" htmlFor="eng-ua">
                How the tools identify themselves
              </label>
              <div className="select-box">
                <select id="eng-ua" className="select" value={form.user_agent_mode}
                        onChange={(e) => set({ user_agent_mode: e.target.value })}>
                  <option value="">
                    Follow the server default{identities?.environment_default
                      ? ` (${identities.environment_default})` : ''}
                  </option>
                  {(identities?.items || []).map((i) => (
                    <option key={i.id} value={i.id}>{i.label}</option>
                  ))}
                </select>
              </div>
              {/* The note for the selected entry, which for a browser is the
                  User-Agent string itself - the thing the operator is actually
                  choosing, and the thing they will be asked about later. */}
              <span className="field__hint">
                {(identities?.items || []).find((i) => i.id === form.user_agent_mode)?.note
                  || identities?.caveat
                  || 'Loading…'}
              </span>
            </div>
            {form.user_agent_mode === 'custom' && (
              <div className="field">
                <label className="field__label" htmlFor="eng-ua-custom">User-Agent string</label>
                <input id="eng-ua-custom" className="input" placeholder="MyCorp-Scanner/1.0"
                       value={form.user_agent}
                       onChange={(e) => set({ user_agent: e.target.value })} />
                <span className="field__hint">
                  The other headers are matched to the engine this string claims —
                  a Firefox User-Agent sending Chrome client hints stands out more
                  than no User-Agent at all.
                </span>
              </div>
            )}
            {identities?.caveat && form.user_agent_mode && (
              <p className="field__hint" style={{ marginTop: -8 }}>{identities.caveat}</p>
            )}

            <div className="form-sub">Run options</div>
            <div className="checks">
              <Check checked={form.require_approval} onChange={(v) => set({ require_approval: v })}>
                <b>Require my approval</b> before the exploitation phase.
              </Check>
              <Check checked={form.allow_active_exploit} onChange={(v) => set({ allow_active_exploit: v, allow_sql_os_cmd: v && form.allow_sql_os_cmd, allow_data_proof: v && form.allow_data_proof })}>
                <b>Prove impact:</b> run a benign read-only command through confirmed injections (RCE/SQLi) to demonstrate access. Never destructive.
              </Check>
              {form.allow_active_exploit && (
                <div className="check-nested">
                  <div className="danger-note">sensitive - only on targets you fully own</div>
                  <Check checked={form.allow_sql_os_cmd} onChange={(v) => set({ allow_sql_os_cmd: v })}>
                    Also attempt OS command execution through SQLi <code>(sqlmap --os-cmd)</code>.
                  </Check>
                  <Check checked={form.allow_data_proof} onChange={(v) => set({ allow_data_proof: v })}>
                    Prove a data breach: retrieve a small bounded sample <code>(&le;3 rows)</code> of sensitive tables via confirmed SQLi.
                  </Check>
                </div>
              )}
            </div>

            <div className="attest">
              <Check checked={form.attest} onChange={(v) => set({ attest: v })}>
                <b>I am authorized</b> to perform security testing against this target.
              </Check>
            </div>

            <div className="form-actions">
              <button type="submit" className="btn btn--solid">Create engagement</button>
            </div>
          </form>
        </div>
      </div>

      <div className="card">
        <div className="card__head">
          <span className="card__title">Engagements <span style={{ color: 'var(--text-faint)' }}>({items.length})</span></span>
          <button className="btn btn--muted" onClick={load}>Refresh</button>
        </div>
        {items.length === 0 ? (
          <div className="card__body"><div className="empty">No engagements yet.</div></div>
        ) : (
          <table className="tbl">
            <thead><tr><th>ID</th><th>Target</th><th>Status</th><th>Progress</th><th>Findings</th><th></th></tr></thead>
            <tbody>
              {items.map((e) => (
                <tr key={e.id} className={'clickable' + (e.id === selectedId ? ' selected' : '')} tabIndex={0} onClick={() => setSelectedId(e.id)} onKeyDown={activateOnKey(() => setSelectedId(e.id))}>
                  <td className="mono" style={{ color: 'var(--text-secondary)' }}>{e.id}</td>
                  <td className="mono truncate" style={{ maxWidth: 220 }} title={e.target_url}>{e.target_url}</td>
                  <td><span className={'st eng-' + e.status}>{e.status}</span></td>
                  <td><div className="eng-progress"><div className="eng-progress__bar"><div className="eng-progress__fill" style={{ width: (e.progress || 0) + '%' }}></div></div><span className="eng-progress__n">{e.progress || 0}%</span></div></td>
                  <td><SevMini sev={sevOf(e)} /></td>
                  <td onClick={(ev) => ev.stopPropagation()}>{e.status === 'authorized' && <span className="text-link" onClick={() => nav(`/engagements/${e.id}/live`)}>live view</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {selected && (
        <div className="card inspector">
          <div className="card__head">
            <span className="card__title">Engagement {selected.id}</span>
            <div style={{ display: 'flex', gap: 8 }}>
              {selected.status === 'authorized' && <button className="btn" onClick={() => nav(`/engagements/${selected.id}/live`)}>Open live view</button>}
              <button className="btn" onClick={() => closeEng(selected.id)}>Close</button>
              <button className="btn btn--danger"
                      onClick={() => { setDeleting(selected); setConfirmText(''); }}>
                Delete
              </button>
            </div>
          </div>
          <div className="card__body">
            <div className="insp-cols">
              <dl className="kv">
                <dt>Target</dt><dd>{selected.target_url}</dd>
                <dt>Status</dt><dd className={'eng-' + selected.status}>{selected.status}</dd>
                <dt>Scope</dt><dd>{(selected.scope_hosts || []).join(', ')}</dd>
                <dt>Authorized via</dt><dd>{selected.verification_method || '-'}</dd>
                {/* Worth showing after the fact: "why did their WAF block us"
                    and "why does the client's log say Chrome" are both
                    answered by this one line. */}
                <dt>Scan identity</dt>
                <dd className="mono">
                  {selected.user_agent_mode
                    ? (identities?.items || []).find((i) => i.id === selected.user_agent_mode)?.label
                      || selected.user_agent_mode
                    : `server default${identities?.environment_default ? ` (${identities.environment_default})` : ''}`}
                  {selected.user_agent_mode === 'custom' && selected.user_agent
                    ? ` — ${selected.user_agent}` : ''}
                </dd>
                <dt>Phase</dt><dd>{selected.phase || '-'}</dd>
                <dt>Progress</dt><dd><div className="eng-progress"><div className="eng-progress__bar"><div className="eng-progress__fill" style={{ width: (selected.progress || 0) + '%' }}></div></div><span className="eng-progress__n">{selected.progress || 0}%</span></div></dd>
                <dt>Findings</dt>
                <dd>
                  <SevMini sev={sevOf(selected)} />
                  {selected.pending_findings > 0 && (
                    <span className="eng-pending"> +{selected.pending_findings} awaiting review</span>
                  )}
                </dd>
                <dt>LLM cost</dt>
                <dd className="mono">
                  ${((selected.llm_usage || {}).cost_usd || 0).toFixed(2)}
                  <span className="eng-usage-sub">
                    {' '}&middot; {(((selected.llm_usage || {}).total_tokens || 0) / 1000).toFixed(0)}k tokens
                    {' '}&middot; {(selected.llm_usage || {}).calls || 0} calls
                  </span>
                </dd>
              </dl>
              <div className="radar-wrap">
                <Radar values={radarOf(selected)} />
                <div className="radar-legend">
                  <div style={{ color: 'var(--text-secondary)', marginBottom: 4 }}>Coverage by area</div>
                  {COV_AXES.map((a, i) => <div key={a} style={{ color: 'var(--text-faint)' }}>{a} <span style={{ color: 'var(--text-primary)' }}>{radarOf(selected)[i]}%</span></div>)}
                </div>
              </div>
            </div>
            <p className="inspector__note">Authorized. Open the live view to run the autonomous test and watch recon, findings, kill-chains and the report build in real time.</p>
          </div>
        </div>
      )}

      {deleting && (
        <div className="card cfm">
          <div className="card__head">
            <span className="card__title">Delete {deleting.target_host || deleting.id}?</span>
          </div>
          <div className="card__body">
            <p className="intro">
              Removes this engagement and everything it produced - findings, chains,
              coverage, assets, jobs, events, approvals and its token accounting.
              Recovered source and cached JavaScript on disk go too, unless another
              engagement still targets the same host.
            </p>
            <p className="intro">
              The <b>audit trail</b> and the <b>cross-engagement memory</b> are kept
              on purpose: the first records what was authorised and what ran, the
              second is what makes the next run smarter. This cannot be undone.
            </p>
            <label className="rfind__lbl" htmlFor="cfm-host">
              Type <code>{deleting.target_host || deleting.id}</code> to confirm
            </label>
            <div style={{ display: 'flex', gap: 8, marginTop: 6, flexWrap: 'wrap' }}>
              <input id="cfm-host" className="input" value={confirmText} autoFocus
                     onChange={(ev) => setConfirmText(ev.target.value)} />
              <button className="btn btn--danger"
                      disabled={confirmText !== (deleting.target_host || deleting.id)}
                      onClick={() => deleteEng(deleting)}>
                Delete permanently
              </button>
              <button className="btn btn--muted"
                      onClick={() => { setDeleting(null); setConfirmText(''); }}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
