import { useEffect, useState } from 'react';
import { api } from '../lib/api.js';
import { useEngagements } from '../lib/useApi.js';
import { Async, Card, Notice } from '../components/ui.jsx';
import { useApi } from '../lib/useApi.js';

const SEV_HEX = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#06b6d4', info: '#525252' };
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export default function Reports() {
  // One shared picker: five pages each rebuilt this and each swallowed
  // its failure, so a dead backend looked exactly like an empty install.
  const { engagements, engId, setEngId, error: engError, reload: reloadEngagements } = useEngagements();
  // Retest comparison. The endpoint shipped with no caller at all: you could
  // compute what a client fixed and what came back, and never see it.
  const [against, setAgainst] = useState('');
  const diff = useApi(() => api.engagements.diff(engId, against), [], { immediate: false });
  const [state, setState] = useState(null);
  const [tmpl, setTmpl] = useState('technical');
  const [open, setOpen] = useState([]);
  const [toast, setToast] = useState(null);
  const flash = (m) => { setToast(m); setTimeout(() => setToast(null), 2000); };
  const tech = tmpl === 'technical';

  useEffect(() => {
    if (!engId) return;
    api.engagements.state(engId).then(setState).catch(() => setState(null));
  }, [engId]);

  const eng = state?.engagement;
  const findings = (state?.validated_findings || []).filter((f) => f.status !== 'false_positive')
    .slice().sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
  const chains = state?.chains || [];
  const vsum = state?.validation_summary || {};
  const dist = findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {});
  const total = findings.length;
  const maxd = Math.max(...['critical', 'high', 'medium', 'low'].map((s) => dist[s] || 0), 1);
  const [narrative, setNarrative] = useState(null);
  const [writing, setWriting] = useState(false);

  // The deterministic report below is assembled from the findings. This asks
  // the LLM for the prose version - the executive framing a client reads
  // first, which templates are bad at.
  async function writeNarrative() {
    if (!eng) return;
    setWriting(true); setNarrative(null);
    try {
      const r = await api.llm.report({
        title: `Penetration Test - ${eng.target_host || eng.target_url}`,
        scope: (eng.scope_hosts || []).join(', '),
      });
      setNarrative(r.markdown || '(empty)');
    } catch (e) {
      setNarrative(`Could not generate: ${e.message}`);
    } finally { setWriting(false); }
  }

  const toggle = (id) => setOpen((o) => o.includes(id) ? o.filter((x) => x !== id) : [...o, id]);

  function exportAs(fmt) {
    if (!engId) return;
    const map = { md: 'md', print: 'pdf', sarif: 'sarif' };
    window.open(`/api/engagements/${engId}/report?format=${map[fmt] || 'md'}`, '_blank');
  }

  // JSON goes through the api layer rather than window.open: the browser would
  // render it as a page instead of saving it, and the operator wants the file.
  async function exportJson() {
    if (!engId) return;
    try {
      const data = await api.engagements.reportJson(engId);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `syphax-${engId}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setNarrative(`JSON export failed: ${e.message}`);
    }
  }

  return (
    <div className="page">
      <Notice kind="error" title="Could not load engagements"
              message={engError} onRetry={reloadEngagements} />
      <div className="rep-bar">
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <div className="select-box"><select className="select" value={engId} onChange={(e) => setEngId(e.target.value)}>
            {engagements.length === 0 && <option value="">no engagements</option>}
            {engagements.map((e) => <option key={e.id} value={e.id}>{e.target_host || e.target_url}</option>)}
          </select></div>
          <div className="seg">
            <button className={tmpl === 'executive' ? 'on' : ''} onClick={() => setTmpl('executive')}>Executive</button>
            <button className={tmpl === 'technical' ? 'on' : ''} onClick={() => setTmpl('technical')}>Technical</button>
          </div>
        </div>
        <div className="rep-formats">
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-faint)', marginRight: 4 }}>export:</span>
          <button className="btn btn--muted" onClick={() => exportAs('md')}>Markdown</button>
          <button className="btn btn--muted" onClick={() => exportAs('print')}>PDF</button>
          <button className="btn btn--muted" onClick={exportJson}>JSON</button>
          <button className="btn btn--muted" onClick={() => exportAs('sarif')}>SARIF</button>
          <button className="btn" onClick={writeNarrative} disabled={!engId || writing}>
            {writing ? 'Writing...' : 'LLM narrative'}
          </button>
        </div>
      </div>

      {narrative && (
        <div className="card">
          <div className="card__head">
            <span className="card__title">LLM narrative</span>
            <span className="card__meta">draft &middot; review before sending</span>
          </div>
          <div className="card__body">
            <pre className="rep-narrative">{narrative}</pre>
          </div>
        </div>
      )}

      {!eng ? <div className="card"><div className="card__body"><div className="empty">Select an engagement to assemble its report.</div></div></div> : (
        <div className="doc">
          <div className="doc__brand"><span className="doc__wm">syphax</span><span className="doc__cls">confidential</span></div>
          <h1 className="doc__title">Web Application Penetration Test</h1>
          <div className="doc__sub">{eng.target_url}</div>

          <div className="sec">
            <div className="sec__h">Engagement</div>
            <dl className="meta-grid">
              <dt>Target</dt><dd>{eng.target_url}</dd>
              <dt>Scope</dt><dd>{(eng.scope_hosts || []).join(', ')}</dd>
              <dt>Authorized via</dt><dd>{eng.verification_method || '-'}</dd>
              <dt>Engagement</dt><dd>{eng.id}</dd>
            </dl>
          </div>

          <div className="sec">
            <div className="sec__h">Executive summary</div>
            <p>The autonomous assessment of <strong>{eng.target_url}</strong> identified <strong>{total} validated finding(s)</strong>, including <strong>{dist.critical || 0} critical</strong> and <strong>{dist.high || 0} high</strong>-severity issues. <strong>{vsum.confirmed || 0}</strong> were confirmed with a safe, read-only proof.</p>
            <div className="sevdist" style={{ marginTop: 16 }}>
              {['critical', 'high', 'medium', 'low'].map((s) => (
                <div key={s} className="sevdist__row">
                  <span className="sevdist__l" style={{ color: SEV_HEX[s] }}>{s}</span>
                  <span className="sevdist__bar"><span className="sevdist__fill" style={{ width: ((dist[s] || 0) / maxd * 100) + '%', background: SEV_HEX[s] }}></span></span>
                  <span className="sevdist__n">{dist[s] || 0}</span>
                </div>
              ))}
            </div>
          </div>

          {chains.length > 0 && (
            <div className="sec">
              <div className="sec__h">Attack narrative (kill-chain)</div>
              {chains.map((c) => (
                <div key={c.id} style={{ marginBottom: 12 }}>
                  <div style={{ fontWeight: 600, marginBottom: 6 }}>{c.title}</div>
                  <div className="kc">
                    {(c.steps || []).map((st, i) => (
                      <span key={i}>{i > 0 ? <span className="kc__arrow">-&gt;</span> : null}<span className="kc__node">{st.action}</span></span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}

          <div className="sec">
            <div className="sec__h">Findings ({findings.length})</div>
            {findings.map((f) => {
              const isOpen = open.includes(f.id);
              return (
                <div key={f.id} className="rfind">
                  <div className="rfind__head" onClick={() => toggle(f.id)}>
                    <span className={'sev sev--' + f.severity}>{f.severity}</span>
                    <span className="rfind__title">{f.title}</span>
                    <span className={'vstatus vstatus--' + f.status} style={{ marginLeft: 'auto' }}>{f.status}</span>
                  </div>
                  {isOpen && (
                    <div className="rfind__body">
                      <div className="rfind__target">{f.target}</div>
                      <div className="rfind__lbl">Class / tool</div>
                      <div className="rfind__txt">{f.vuln_class} &middot; {f.tool}{f.method ? ' · ' + f.method : ''}</div>
                      {tech && f.evidence && <><div className="rfind__lbl">Evidence</div><pre className="rfind__pre">{f.evidence}</pre></>}
                      {tech && f.poc && <><div className="rfind__lbl">Proof of concept</div><pre className="rfind__pre poc">{f.poc}</pre></>}
                    </div>
                  )}
                </div>
              );
            })}
            {findings.length === 0 && <div className="empty">No validated findings yet.</div>}
          </div>
        </div>
      )}
      {engId && (
        <Card title="Retest comparison"
              meta={diff.data ? `${diff.data.counts.fixed} fixed · ${diff.data.counts.new} new` : null}>
          <p className="intro">
            Compare this engagement with an earlier one on the same target: what the
            client fixed, what came back, and what is new.
          </p>
          <div className="row" style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <label className="rfind__lbl" htmlFor="diff-against">Earlier engagement</label>
            <div className="select-box">
              <select id="diff-against" className="select" value={against}
                      onChange={(e) => setAgainst(e.target.value)}>
                <option value="">select…</option>
                {engagements.filter((e) => e.id !== engId).map((e) => (
                  <option key={e.id} value={e.id}>{e.target_host || e.target_url} — {e.id.slice(0, 8)}</option>
                ))}
              </select>
            </div>
            <button className="btn" disabled={!against || diff.loading}
                    onClick={() => diff.reload()}>
              {diff.loading ? 'Comparing…' : 'Compare'}
            </button>
          </div>
          {(diff.data || diff.error) && (
            <div style={{ marginTop: 12 }}>
              <Async loading={diff.loading} error={diff.error} data={diff.data}
                     onRetry={() => diff.reload()} empty="Nothing to compare.">
                <>
                  <p className="intro">{diff.data?.summary}</p>
                  <div className="stats">
                    <div className="stat stat--alert"><div className="stat__l">New</div><div className="stat__v">{diff.data?.counts.new ?? 0}</div></div>
                    <div className="stat"><div className="stat__l">Fixed</div><div className="stat__v">{diff.data?.counts.fixed ?? 0}</div></div>
                    <div className="stat"><div className="stat__l">Unchanged</div><div className="stat__v">{diff.data?.counts.unchanged ?? 0}</div></div>
                    <div className="stat"><div className="stat__l">Worsened</div><div className="stat__v">{diff.data?.counts.worsened ?? 0}</div></div>
                    <div className="stat"><div className="stat__l">Improved</div><div className="stat__v">{diff.data?.counts.improved ?? 0}</div></div>
                  </div>
                  {['new', 'worsened', 'fixed'].map((k) => (
                    (diff.data?.[k] || []).length > 0 && (
                      <div key={k} style={{ marginTop: 10 }}>
                        <div className="rfind__lbl">{k}</div>
                        {(diff.data[k] || []).slice(0, 20).map((f, i) => (
                          <div key={i} className="calls__row">
                            <span className={'sev sev--' + (f.severity || 'info')}>{f.severity}</span>
                            <span className="calls__model">{f.title}</span>
                            <span className="calls__n">{f.target}</span>
                          </div>
                        ))}
                      </div>
                    )
                  ))}
                </>
              </Async>
            </div>
          )}
        </Card>
      )}
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
