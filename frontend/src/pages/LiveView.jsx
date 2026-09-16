import { useCallback, useEffect, useRef, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api, getApiKey } from '../lib/api.js';
import { useApi, usePoll } from '../lib/useApi.js';
import TokenPanel from '../components/TokenPanel.jsx';
import { AuditTrail, ChainList, CoverageMatrix } from '../components/live/Panels.jsx';

const PHASES = ['recon', 'mapping', 'vuln_analysis', 'exploitation', 'validation'];
const PHASE_LABEL = { recon: 'Recon', mapping: 'Mapping', vuln_analysis: 'Vuln analysis', exploitation: 'Exploitation', validation: 'Validation' };
const REASON_LABEL = {
  coverage_saturated: 'all applicable tests ran', time_budget: 'time budget reached',
  job_budget: 'job budget reached', no_tools: 'required tools unavailable',
  max_iterations: 'iteration cap reached', stopped: 'stopped by operator',
  exploit_denied: 'exploitation not approved', cancelled: 'cancelled', error: 'stopped after errors',
  llm_budget: 'LLM spend cap reached',
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
  // Replayed proofs, by finding id. The judge already paid a call to produce
  // each one; this is what finally uses it.
  const [proofs, setProofs] = useState({});
  const [memory, setMemory] = useState([]);
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
    } catch (e) {
      // A backend 500 used to look exactly like "no data": the panels just
      // kept their last values while the header still said running.
      console.error('live state refresh failed', e);
    }
  }, [id]);

  useEffect(() => { loadState(); }, [loadState]);
  // What past engagements suggest on this stack. Advisory, so a failure here
  // must not disturb the page.
  useEffect(() => {
    api.engagements.memory(id)
      .then((r) => setMemory(r.lessons || []))
      .catch((e) => console.error('memory unavailable', e));
  }, [id]);
  // Poll only while a run can still change. A finished run polled forever,
  // firing two requests every 3s for as long as the tab stayed open.
  const polling = state === null || state?.run?.status === 'running'
    || state?.run?.status === 'queued';
  useEffect(() => {
    if (!polling) return undefined;
    const t = setInterval(() => {
      // Don't poll a tab nobody is looking at: this ran forever otherwise.
      if (document.visibilityState !== 'hidden') loadState();
    }, 3000);
    return () => clearInterval(t);
  }, [loadState, polling]);

  // Token spend, refreshed on the same cadence while the run can still change.
  // usePoll pauses when the tab is hidden and refetches on return.
  const usageFn = useCallback(() => api.engagements.usage(id), [id]);
  const usage = usePoll(usageFn, 5000, { active: polling, deps: [id] });

  // The audit trail is written on every authorisation-relevant action and had
  // no reader: the endpoint existed, the client method existed, and no page
  // ever called it. For an offensive tool that record is the point.
  const auditFn = useCallback(() => api.audit.list({ engagement_id: id, limit: 200 }), [id]);
  const audit = useApi(auditFn, [id], { immediate: false });
  useEffect(() => { if (tab === 'audit') audit.reload(); }, [tab, id]);  // eslint-disable-line react-hooks/exhaustive-deps

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
  async function analyze() { setBusy(true); try { await api.engagements.analyzeTraffic(id); await loadState(); flash('Deep analysis complete'); } catch (e) { flash(e.message); } finally { setBusy(false); } }
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
  async function verifyProof(fid) {
    setProofs((p) => ({ ...p, [fid]: { outcome: 'running', detail: 'replaying...' } }));
    try {
      const r = await api.engagements.verifyProof(fid);
      setProofs((p) => ({ ...p, [fid]: r }));
      if (r.outcome === 'held' || r.outcome === 'did_not_hold') await loadState();
    } catch (e) {
      setProofs((p) => ({ ...p, [fid]: { outcome: 'error', detail: e.message } }));
    }
  }

  async function toggleJob(jid) {
    if (openJob === jid) { setOpenJob(null); setJobDetail(null); return; }
    setOpenJob(jid); setJobDetail(null);
    try { setJobDetail(await api.scans.get(jid)); }
    catch (e) { flash(e.message); setOpenJob(null); }
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
    { key: 'tokens', label: 'Tokens' },
    { key: 'audit', label: 'Audit' },
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
        {run0.stale && (
          <><span>&middot;</span><span className="run-reason">no worker reporting &mdash; Run reclaims it</span></>
        )}
        {!active && run0.stop_reason && (
          <><span>&middot;</span><span className="run-reason">{REASON_LABEL[run0.stop_reason] || run0.stop_reason}</span></>
        )}
        <span>&middot;</span><span>iteration <b>{run0.iterations || 0}</b></span>
        <span>&middot;</span><span><b>{run0.jobs_launched || 0}</b> jobs launched</span>
        <span>&middot;</span><span><b>{vsum.confirmed || 0}</b> confirmed</span>
      </div>

      {memory.length > 0 && (
        <div className="mem-strip">
          <span className="mem-strip__l">From past engagements on this stack</span>
          {memory.slice(0, 6).map((l) => (
            <span key={l.technology + l.vuln_class} className="mem-strip__item"
                  title={`${l.confirmed} confirmed / ${l.observations} seen${l.example_title ? ' · e.g. ' + l.example_title : ''}`}>
              {l.vuln_class} <b>{Math.round(l.precision * 100)}%</b>
            </span>
          ))}
        </div>
      )}

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
                <div className="stat"><div className="stat__l">Jobs launched</div><div className="stat__v">{run0.jobs_launched || 0}</div></div>
                <div className="stat"><div className="stat__l">Tokens</div><div className="stat__v">{((llm.total_tokens || 0) / 1000).toFixed(1)}<small>k</small></div></div>
                <div className="stat"><div className="stat__l">API cost</div><div className="stat__v"><small>$</small>{(llm.cost_usd || 0).toFixed(4)}</div></div>
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

      {tab === 'coverage' && <CoverageMatrix coverage={coverage} covSummary={covSummary} />}
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
                  {/* An oracle decided this, or a scanner pattern matched it.
                      Showing both identically is the conflation the report
                      also had. */}
                  <span className={'proof proof--' + (f.proven ? 'yes' : 'no')}
                        title={f.proven
                          ? 'Reproduced against the target by an oracle'
                          : 'Reported by a scanner; no oracle could decide it'}>
                    {f.proven ? 'proven' : 'unverified'}
                  </span>
                </div>
                <div className="finding__title">{f.title}</div>
                <div className="finding__target">{f.target}</div>
                <div className="finding__meta">{f.tool} &middot; {f.vuln_class}{f.method ? ' · ' + f.method : ''}</div>
                {f.corroboration && f.corroboration.note && (
                  <div className={'corr' + (f.corroboration.demoted ? ' corr--down' : '')}>
                    {f.corroboration.demoted ? '↓ ' : (f.corroboration.independent > 1 ? '↑ ' : '')}
                    {f.corroboration.note}
                  </div>
                )}
                {f.poc && <pre className="finding__poc">{f.poc}</pre>}
                {(f.metadata || {}).suggested_proof && (
                  <div className="finding__proof">
                    <span className="finding__proof-l">Suggested proof</span>
                    <code>{(f.metadata.suggested_proof.method || 'GET')} {f.metadata.suggested_proof.url}</code>
                    <span className="finding__proof-l">expects</span>
                    <code>{f.metadata.suggested_proof.expect}</code>
                    {proofs[f.id] && <div className={'finding__proof-r finding__proof-r--' + proofs[f.id].outcome}>{proofs[f.id].outcome}: {proofs[f.id].detail}</div>}
                  </div>
                )}
                <div className="finding__actions">
                  <button className="btn btn--muted btn--sm" onClick={() => retest(f.id)}>Retest</button>
                  {(f.metadata || {}).suggested_proof && (
                    <button className="btn btn--muted btn--sm" onClick={() => verifyProof(f.id)}>Verify proof</button>
                  )}
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

      {tab === 'chains' && <ChainList chains={chains} />}
      {tab === 'audit' && <AuditTrail audit={audit} time={time} />}
      {tab === 'tokens' && (
        <TokenPanel usage={usage.data} loading={usage.loading} error={usage.error}
                    onRetry={usage.reload} />
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
