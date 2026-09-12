import { useCallback, useEffect, useRef, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api, getApiKey } from '../lib/api.js';

const PHASES = ['recon', 'mapping', 'vuln_analysis', 'exploitation', 'validation'];
const PHASE_LABEL = { recon: 'Recon', mapping: 'Mapping', vuln_analysis: 'Vuln analysis', exploitation: 'Exploitation', validation: 'Validation' };
const REASON_LABEL = {
  coverage_saturated: 'all applicable tests ran', time_budget: 'time budget reached',
  job_budget: 'job budget reached', no_tools: 'required tools unavailable',
  max_iterations: 'iteration cap reached', stopped: 'stopped by operator',
  exploit_denied: 'exploitation not approved', cancelled: 'cancelled', error: 'stopped after errors',
};
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const CATS = [
  { key: 'all', label: 'All' }, { key: 'recon', label: 'Recon' }, { key: 'enumeration', label: 'Enumeration' },
  { key: 'access_control', label: 'Access control' }, { key: 'injection', label: 'Injection' },
  { key: 'auth_secrets', label: 'Auth & secrets' }, { key: 'config', label: 'Server & config' }, { key: 'other', label: 'Other' },
];

export default function LiveView() {
  const { id } = useParams();
  const nav = useNavigate();
  const [state, setState] = useState(null);
  const [events, setEvents] = useState([]);
  const [approvals, setApprovals] = useState([]);
  const [tab, setTab] = useState('console');
  const [cat, setCat] = useState('all');
  const [openJob, setOpenJob] = useState(null);
  const [jobDetail, setJobDetail] = useState(null);
  const [openReq, setOpenReq] = useState(null);
  const [busy, setBusy] = useState(false);
  const [toast, setToast] = useState(null);
  const wsRef = useRef(null);
  const lastIdRef = useRef(0);
  const agentRef = useRef(null);
  const verboseRef = useRef(null);
  const flash = (m) => { setToast(m); setTimeout(() => setToast(null), 2200); };

  const loadState = useCallback(async () => {
    try {
      const [s, a] = await Promise.all([api.engagements.state(id), api.engagements.approvals(id)]);
      setState(s);
      setApprovals((a.items || []).filter((x) => x.decision === null));
    } catch (e) { /* ignore */ }
  }, [id]);

  useEffect(() => { loadState(); }, [loadState]);
  // Poll only while a run can still change. A finished run polled forever,
  // firing two requests every 3s for as long as the tab stayed open.
  const polling = state === null || state?.run?.status === 'running'
    || state?.run?.status === 'queued';
  useEffect(() => {
    if (!polling) return undefined;
    const t = setInterval(loadState, 3000);
    return () => clearInterval(t);
  }, [loadState, polling]);

  useEffect(() => {
    let closed = false;
    let retry = null;
    let attempt = 0;

    // The server closes the socket on any DB hiccup. With no onclose handler the
    // console went silent for the rest of the run while the UI still said
    // "running", so reconnect with backoff and resume from the last id we saw.
    const connect = () => {
      if (closed) return;
      const proto = location.protocol === 'https:' ? 'wss' : 'ws';
      // A browser cannot set headers on a WebSocket handshake, so the optional
      // API key travels as ?key= (the backend checks it before accept()).
      const k = getApiKey();
      const ws = new WebSocket(`${proto}://${location.host}/ws/engagements/${id}/stream?after=${lastIdRef.current}`
        + (k ? `&key=${encodeURIComponent(k)}` : ''));
      wsRef.current = ws;
      ws.onopen = () => { attempt = 0; };
      ws.onmessage = (msg) => {
        try {
          const ev = JSON.parse(msg.data);
          // Drop anything we already have: a resume replays the boundary event.
          if (ev.id && ev.id <= lastIdRef.current) return;
          lastIdRef.current = Math.max(lastIdRef.current, ev.id || 0);
          setEvents((p) => [...p.slice(-500), ev]);
        } catch { /* a malformed frame must not kill the stream */ }
      };
      const reconnect = () => {
        if (closed || wsRef.current !== ws) return;
        attempt += 1;
        retry = setTimeout(connect, Math.min(1000 * 2 ** (attempt - 1), 15000));
      };
      ws.onclose = reconnect;
      ws.onerror = () => { try { ws.close(); } catch { /* onclose handles it */ } };
    };

    (async () => {
      try {
        const back = await api.engagements.events(id, 0);
        if (closed) return;
        setEvents(back.items || []);
        lastIdRef.current = (back.items || []).reduce((m, e) => Math.max(m, e.id), 0);
      } catch { /* backfill is best-effort; the socket still streams */ }
      if (closed) return;          // unmounted during the backfill
      connect();
    })();

    return () => {
      closed = true;
      if (retry) clearTimeout(retry);
      const ws = wsRef.current;
      wsRef.current = null;
      if (ws) { ws.onclose = null; ws.close(); }
    };
  }, [id]);

  useEffect(() => {
    agentRef.current?.scrollTo(0, agentRef.current.scrollHeight);
    verboseRef.current?.scrollTo(0, verboseRef.current.scrollHeight);
  }, [events, tab]);

  async function run() { setBusy(true); try { await api.engagements.run(id); await loadState(); } catch (e) { flash(e.message); } finally { setBusy(false); } }
  async function stop() { setBusy(true); try { await api.engagements.stop(id); await loadState(); } catch (e) { flash(e.message); } finally { setBusy(false); } }
  async function analyze() { setBusy(true); try { const r = await api.engagements.analyzeTraffic(id); await loadState(); flash('Deep analysis complete'); } catch (e) { flash(e.message); } finally { setBusy(false); } }
  // Validation runs at the end of an autonomous run. This re-runs it on
  // demand, which is what you want after adding findings by hand from the
  // Scans page - otherwise they sit unvalidated until the next full run.
  async function revalidate() {
    setBusy(true);
    try {
      const r = await api.engagements.validate(id);
      await loadState();
      const st = r.stats || {};
      flash(`Validated ${st.validated ?? st.total ?? 0} finding(s) · ${r.chains ?? 0} chain(s)`);
    } catch (e) { flash(e.message); } finally { setBusy(false); }
  }
  async function decide(aid, decision) { try { await api.engagements.decideApproval(id, aid, decision); await loadState(); } catch (e) { flash(e.message); } }
  async function retest(fid) {
    flash('Re-testing...');
    try {
      const r = await api.engagements.retestFinding(id, fid);
      await loadState();
      flash(r.status === 'false_positive' ? 'Retest: no longer reproduced' : 'Retest complete');
    } catch (e) { flash(e.message); }
  }
  async function toggleJob(jid) {
    if (openJob === jid) { setOpenJob(null); setJobDetail(null); return; }
    setOpenJob(jid); setJobDetail(null);
    try { setJobDetail(await api.scans.get(jid)); } catch { /* ignore */ }
  }

  const s = state || {};
  const eng = s.engagement || {};
  const run0 = s.run || {};
  const host = eng.target_host || '';
  const tech = s.technologies || [];
  const llm = s.llm_usage || {};
  const vsum = s.validation_summary || {};
  const assets = s.assets || [];
  const jobs = s.jobs || [];
  const coverage = s.coverage || [];
  const covSummary = s.coverage_summary || {};
  const findingsAll = s.validated_findings || [];
  const chains = s.chains || [];
  const active = run0.status === 'running' || run0.status === 'queued';

  const info = events.filter((e) => e.level !== 'verbose');
  const verbose = events.filter((e) => e.level === 'verbose');
  const phaseIdx = PHASES.indexOf(run0.phase);
  const time = (ts) => new Date((ts || 0) * 1000).toLocaleTimeString('en-US', { hour12: false });

  const TABS = [
    { key: 'console', label: 'Console' },
    { key: 'assets', label: 'Assets', count: assets.length },
    { key: 'coverage', label: 'Coverage', count: coverage.length },
    { key: 'jobs', label: 'Jobs', count: jobs.length },
    { key: 'findings', label: 'Findings', count: findingsAll.length, alert: true },
    { key: 'chains', label: 'Chains', count: chains.length },
  ];
  const findings = (cat === 'all' ? findingsAll : findingsAll.filter((f) => (f.category || 'other') === cat))
    .slice().sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));

  const ConsoleLine = ({ e, prompt }) => (
    <div className={`cline ev--${e.type}${e.severity ? ' sev-' + e.severity : ''}`}>
      <span className="cline__ts">{time(e.ts)}</span>
      {prompt && e.type === 'command' ? <span className="cline__prompt">$</span> : null}
      <span className="cline__tag">[{e.type}]</span>
      <span className="cline__msg">{e.message}</span>
    </div>
  );

  return (
    <div className="page">
      <div className="lv-head">
        <div className="lv-title"><h1>Live view</h1>{host && <span className="lv-title__host">&middot; {host}</span>}</div>
        <div className="lv-actions">
          <button className="btn btn--muted" onClick={() => nav('/engagements')}>Back</button>
          {!active && <button className="btn" onClick={run} disabled={busy}>Run</button>}
          {active && <button className="btn btn--danger" onClick={stop} disabled={busy}>Stop</button>}
          <button className="btn" onClick={analyze} disabled={busy}>Deep analysis</button>
          <button className="btn" onClick={revalidate} disabled={busy} title="Re-run validation and chain building over the current findings">Re-validate</button>
          <a className="btn btn--muted" href={`/api/engagements/${id}/report.md`} target="_blank" rel="noreferrer">Report .md</a>
          <a className="btn btn--muted" href={`/api/engagements/${id}/report.html`} target="_blank" rel="noreferrer">Report (print)</a>
        </div>
      </div>

      <div className="stepper">
        {PHASES.map((p, i) => {
          const st = i < phaseIdx ? 'done' : i === phaseIdx ? 'active' : 'pending';
          return <div key={p} className={'step step--' + st}><span className="step__name">{PHASE_LABEL[p]}</span></div>;
        })}
      </div>
      <div className="run-meta">
        {active && <span className="live-dot pulse"></span>}
        Run: <b className={active ? 'run-status--running' : ''}>{run0.status || 'not started'}</b>
        {!active && run0.stop_reason && (
          <><span>&middot;</span><span className="run-reason">{REASON_LABEL[run0.stop_reason] || run0.stop_reason}</span></>
        )}
        <span>&middot;</span><span>iteration <b>{run0.iterations || 0}</b></span>
        <span>&middot;</span><span><b>{run0.jobs_launched || 0}</b> jobs launched</span>
        <span>&middot;</span><span><b>{vsum.confirmed || 0}</b> confirmed</span>
      </div>

      {approvals.map((a) => (
        <div key={a.id} className="approval">
          <div className="approval__t">Approval required</div>
          <div className="approval__d">{a.summary}</div>
          <div className="approval__meta">tools: {(a.tools || []).join(', ')} &middot; targets: {(a.targets || []).join(', ')}</div>
          <div className="approval__row">
            <button className="btn" onClick={() => decide(a.id, 'approved')}>Approve exploitation</button>
            <button className="btn btn--danger" onClick={() => decide(a.id, 'denied')}>Deny</button>
          </div>
        </div>
      ))}

      <div className="tabs">
        {TABS.map((t) => (
          <button key={t.key} className={'tab' + (tab === t.key ? ' tab--active' : '')} onClick={() => setTab(t.key)}>
            {t.label}
            {t.count != null ? <span className={'tab__count' + (t.alert && t.count > 0 && tab !== t.key ? ' tab__count--alert' : '')}>{t.count}</span> : null}
          </button>
        ))}
      </div>

      {tab === 'console' && (
        <>
          <div className="card">
            <div className="card__head"><span className="card__title">Agent console</span><span className="card__meta">{active && <span className="live-dot pulse" style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--term-ok)' }}></span>} {info.length} events</span></div>
            <div className="console" ref={agentRef}>
              {info.length === 0 && <div className="console__empty">No events yet. Press Run to start the engagement.</div>}
              {info.map((e) => <ConsoleLine key={e.id} e={e} />)}
            </div>
          </div>
          <div className="card">
            <div className="card__head"><span className="card__title">Verbose console</span><span className="card__meta">raw tool I/O</span></div>
            <div className="card__body" style={{ paddingTop: 12, paddingBottom: 12 }}>
              <div className="console console--verbose" ref={verboseRef}>
                {verbose.length === 0 && <div className="console__empty">Commands, jobs, findings and validation detail show here.</div>}
                {verbose.map((e) => <ConsoleLine key={e.id} e={e} prompt />)}
              </div>
            </div>
          </div>
          <div className="card">
            <div className="card__head"><span className="card__title">Surface &amp; cost</span></div>
            <div className="card__body">
              <div className="stats">
                <div className="stat"><div className="stat__l">Assets</div><div className="stat__v">{assets.length}</div></div>
                <div className="stat"><div className="stat__l">Technologies</div><div className="stat__v">{tech.length}</div></div>
                <div className="stat stat--alert"><div className="stat__l">Confirmed vulns</div><div className="stat__v">{vsum.confirmed || 0}</div></div>
                <div className="stat"><div className="stat__l">False-positive rate</div><div className="stat__v">{vsum.false_positive_rate_pct ?? 0}<small>%</small></div></div>
                <div className="stat"><div className="stat__l">LLM calls</div><div className="stat__v">{llm.calls || 0}</div></div>
                <div className="stat"><div className="stat__l">Tokens</div><div className="stat__v">{((llm.total_tokens || 0) / 1000).toFixed(1)}<small>k</small></div></div>
                <div className="stat"><div className="stat__l">API cost</div><div className="stat__v"><small>$</small>{(llm.cost_usd || 0).toFixed(4)}</div></div>
                <div className="stat"><div className="stat__l">Jobs launched</div><div className="stat__v">{run0.jobs_launched || 0}</div></div>
              </div>
              {tech.length > 0 && <div className="techrow"><span className="stat__l" style={{ margin: 0 }}>Tech:</span>{tech.map((t) => <span key={t} className="tech-chip">{t}</span>)}</div>}
            </div>
          </div>
        </>
      )}

      {tab === 'assets' && (
        <div className="card">
          <div className="card__head"><span className="card__title">Discovered assets</span><span className="card__meta">{assets.length} total</span></div>
          <div className="tbl-scroll">
            <table className="tbl">
              <thead><tr><th>Kind</th><th>Value</th><th>Source</th><th>Params</th><th>HTTPS</th></tr></thead>
              <tbody>
                {assets.map((a, i) => (
                  <tr key={i}>
                    <td><span className="st">{a.kind}</span></td>
                    <td className="mono truncate" style={{ maxWidth: 360 }} title={a.value}>{a.value}</td>
                    <td className="mono" style={{ color: 'var(--text-faint)' }}>{a.source}</td>
                    <td>{a.has_params ? <span className="st">yes</span> : <span style={{ color: 'var(--text-faint)' }}>-</span>}</td>
                    <td>{a.is_https ? <span className="st st--succeeded">yes</span> : <span style={{ color: 'var(--text-faint)' }}>-</span>}</td>
                  </tr>
                ))}
                {assets.length === 0 && <tr><td colSpan={5}><div className="empty">No assets discovered yet.</div></td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'coverage' && (
        <div className="card">
          <div className="card__head"><span className="card__title">Methodology coverage</span><span className="card__meta">OWASP WSTG &middot; MITRE ATT&amp;CK</span></div>
          <div className="card__body">
            <div className="cov-summary">
              {Object.entries(covSummary).map(([k, v]) => <span key={k} className={k === 'done' ? 'hit' : ''}>{k}<b>{v}</b></span>)}
              {Object.keys(covSummary).length === 0 && <span style={{ color: 'var(--text-faint)' }}>Nothing run yet.</span>}
            </div>
          </div>
          <div className="tbl-scroll">
            <table className="tbl">
              <thead><tr><th>Catalog item</th><th>Asset</th><th>Status</th></tr></thead>
              <tbody>
                {coverage.map((c, i) => (
                  <tr key={i}>
                    <td className="mono">{c.catalog_item_id}</td>
                    <td className="mono truncate" style={{ maxWidth: 360 }} title={c.asset_value}>{c.asset_value}</td>
                    <td><span className={'st st--' + c.status}>{c.status}</span></td>
                  </tr>
                ))}
                {coverage.length === 0 && <tr><td colSpan={3}><div className="empty">Coverage builds as the run progresses.</div></td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'jobs' && (
        <div className="card">
          <div className="card__head"><span className="card__title">Scan jobs</span><span className="card__meta">click a row for the exact command &amp; output</span></div>
          <div className="tbl-scroll">
            <table className="tbl">
              <thead><tr><th>Tool</th><th>Target</th><th>Status</th><th>Findings</th><th>Duration</th></tr></thead>
              <tbody>
                {jobs.map((j) => (
                  <FragmentRow key={j.id} j={j} open={openJob === j.id} detail={openJob === j.id ? jobDetail : null} onClick={() => toggleJob(j.id)} />
                ))}
                {jobs.length === 0 && <tr><td colSpan={5}><div className="empty">No jobs launched yet.</div></td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'findings' && (
        <div className="card">
          <div className="card__head"><span className="card__title">Validated findings by category</span><span className="card__meta">{findingsAll.length} total &middot; {vsum.confirmed || 0} confirmed</span></div>
          <div className="card__body">
            <div className="subtabs">
              {CATS.map((c) => {
                const n = c.key === 'all' ? findingsAll.length : findingsAll.filter((f) => (f.category || 'other') === c.key).length;
                if (c.key !== 'all' && n === 0) return null;
                return <button key={c.key} className={'subtab' + (cat === c.key ? ' subtab--active' : '')} onClick={() => setCat(c.key)}>{c.label}<span className="subtab__c">{n}</span></button>;
              })}
            </div>
            {findings.map((f) => (
              <div key={f.id} className="finding">
                <div className="finding__top">
                  <span className={'sev sev--' + (f.severity || 'info')}>{f.severity}</span>
                  <span className={'vstatus vstatus--' + f.status}>{f.status} &middot; {Math.round((f.confidence || 0) * 100)}%</span>
                </div>
                <div className="finding__title">{f.title}</div>
                <div className="finding__target">{f.target}</div>
                <div className="finding__meta">{f.tool} &middot; {f.vuln_class}{f.method ? ' · ' + f.method : ''}</div>
                {f.poc && <pre className="finding__poc">{f.poc}</pre>}
                <div className="finding__actions">
                  <button className="btn btn--muted btn--sm" onClick={() => retest(f.id)}>Retest</button>
                  {(f.req || f.resp) && <button className="btn btn--muted btn--sm" onClick={() => setOpenReq(openReq === f.id ? null : f.id)}>{openReq === f.id ? 'Hide' : 'Request / response'}</button>}
                </div>
                {openReq === f.id && (f.req || f.resp) && (
                  <div className="reqresp">
                    <div className="reqresp__col"><div className="reqresp__t">Request</div><pre className="reqresp__pre">{f.req}</pre></div>
                    <div className="reqresp__col"><div className="reqresp__t">Response</div><pre className="reqresp__pre">{f.resp}</pre></div>
                  </div>
                )}
              </div>
            ))}
            {findings.length === 0 && <div className="empty">No findings in this category.</div>}
          </div>
        </div>
      )}

      {tab === 'chains' && (
        <div className="card">
          <div className="card__head"><span className="card__title">Kill-chains</span><span className="card__meta">{chains.length} multi-step paths</span></div>
          <div className="card__body">
            {chains.map((c) => (
              <div key={c.id} className="chain-card">
                <div className="chain-card__top">
                  <span className={'sev sev--' + (c.severity || 'medium')}>{c.severity}</span>
                  <span className="mono" style={{ fontSize: 11, color: 'var(--text-faint)' }}>source: {c.source}</span>
                </div>
                <div className="chain-card__title">{c.title}</div>
                {c.summary && <div className="chain-card__sum">{c.summary}</div>}
                <div className="chain-graph">
                  {(c.steps || []).map((st, i) => (
                    <span key={i}>{i > 0 ? <span className="chain-graph__arrow"></span> : null}<span className="chain-graph__node" title={st.reason}><span className="chain-graph__n">{i + 1}</span><span className="chain-graph__label">{st.action}</span></span></span>
                  ))}
                </div>
                <ol className="chain-steps">
                  {(c.steps || []).map((st, i) => (
                    <li key={i} className="chain-step">
                      <div className="chain-step__rail"><span className="chain-step__dot">{i + 1}</span><span className="chain-step__line"></span></div>
                      <div><div className="chain-step__action">{st.action}</div><div className="chain-step__reason">{st.reason}</div></div>
                    </li>
                  ))}
                </ol>
              </div>
            ))}
            {chains.length === 0 && <div className="empty">No multi-step attack chains identified yet.</div>}
          </div>
        </div>
      )}
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}

function FragmentRow({ j, open, detail, onClick }) {
  const dur = j.duration_ms != null ? (j.duration_ms / 1000).toFixed(1) + 's' : '-';
  return (
    <>
      <tr className={'clickable' + (open ? ' selected' : '')} onClick={onClick}>
        <td><span className="mono">{j.tool}</span></td>
        <td className="mono truncate" style={{ maxWidth: 320, color: 'var(--text-secondary)' }} title={j.target}>{j.target}</td>
        <td><span className={'st st--' + j.status}>{j.status === 'running' ? <span className="blink">{j.status}</span> : j.status}</span></td>
        <td><span className={'fcount ' + ((j.findings_count || 0) > 0 ? 'fcount--hit' : 'fcount--zero')}>{j.findings_count || 0}</span></td>
        <td className="mono" style={{ color: 'var(--text-faint)' }}>{dur}</td>
      </tr>
      {open && (
        <tr><td colSpan={5} style={{ padding: 0 }}>
          <div className="job-detail">
            {!detail ? <div className="empty">Loading...</div> : (
              <>
                <div className="io-label">Command</div>
                <div className="io-block"><span className="p">$</span> {[detail.tool, ...(detail.args || [])].join(' ')} {detail.target && !detail.target.startsWith('(') ? detail.target : ''}</div>
                {detail.error && <div style={{ color: 'var(--severity-critical)', fontFamily: 'var(--font-mono)', fontSize: 11, marginTop: 8 }}>error: {detail.error}</div>}
                {detail.stdout_tail && <><div className="io-label">stdout {detail.exit_code != null ? `· exit ${detail.exit_code}` : ''}</div><div className="io-block">{detail.stdout_tail}</div></>}
                {detail.stderr_tail && <><div className="io-label">stderr</div><div className="io-block">{detail.stderr_tail}</div></>}
              </>
            )}
          </div>
        </td></tr>
      )}
    </>
  );
}
