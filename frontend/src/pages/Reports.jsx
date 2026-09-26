import { useEffect, useMemo, useState } from 'react';
import { api } from '../lib/api.js';
import { useApi, useEngagements } from '../lib/useApi.js';
import { Async, Notice } from '../components/ui.jsx';
import { COV_AXES, Donut, Histogram, Legend, Radar, SEV_HEX } from '../components/Charts.jsx';
import KnowledgeMap from '../components/KnowledgeMap.jsx';
import { mapFromFindings } from '../lib/knowledgeMap.js';

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_BARS = ['critical', 'high', 'medium', 'low'];
const STATUS_HEX = { confirmed: '#22c55e', likely: '#eab308', unconfirmed: '#737373' };

// A report is a deliverable someone reads top-to-bottom, so it gets a real
// document layout: a sticky table of contents on the left that jumps to each
// section, and the section stack on the right. The Executive/Technical toggle
// is a genuine difference - executive collapses the technical noise (attack
// surface, evidence, PoC) that a client's engineers want and their board does
// not - not just a per-finding show/hide.
export default function Reports() {
  const [loadError, setLoadError] = useState(null);
  const { engagements, engId, setEngId, error: engError, reload: reloadEngagements } = useEngagements();
  const [against, setAgainst] = useState('');
  const diff = useApi(() => api.engagements.diff(engId, against), [], { immediate: false });
  const [state, setState] = useState(null);
  const [tmpl, setTmpl] = useState('technical');
  const [open, setOpen] = useState([]);
  const [toast, setToast] = useState(null);
  const [narrative, setNarrative] = useState(null);
  const [writing, setWriting] = useState(false);
  const flash = (m) => { setToast(m); setTimeout(() => setToast(null), 2000); };
  const tech = tmpl === 'technical';

  useEffect(() => {
    if (!engId) { setState(null); return; }
    setState(null); setNarrative(null); setOpen([]);
    api.engagements.state(engId).then(setState)
      .catch((e) => { setState(null); setLoadError(e.message); });
  }, [engId]);

  const eng = state?.engagement;
  const findings = useMemo(() => (state?.validated_findings || [])
    .filter((f) => f.status !== 'false_positive')
    .slice().sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)),
  [state]);
  const chains = state?.chains || [];
  const vsum = state?.validation_summary || {};
  const cov = state?.coverage_summary || {};
  const techs = state?.technologies || [];
  const assets = state?.assets || [];
  const dist = useMemo(() => findings.reduce((a, f) => { a[f.severity] = (a[f.severity] || 0) + 1; return a; }, {}), [findings]);
  const total = findings.length;
  const maxd = Math.max(...SEV_BARS.map((s) => dist[s] || 0), 1);
  const confirmed = vsum.confirmed || 0;
  const covDone = cov.done || cov.succeeded || 0;
  const covTotal = Object.values(cov).reduce((a, n) => a + n, 0);
  const covPct = covTotal ? Math.round((covDone / covTotal) * 100) : 0;

  // Chart data. The radar comes from the engagement summary the list already
  // carries, so no extra fetch. The donut shows the severity mix; the
  // histogram shows how many findings are confirmed vs still awaiting a human.
  const selected = engagements.find((e) => e.id === engId);
  const radarValues = selected?.radar || [0, 0, 0, 0, 0, 0];
  const sevSegments = [...SEV_BARS, 'info']
    .map((s) => ({ label: s, value: dist[s] || 0, color: SEV_HEX[s] }))
    .filter((s) => s.value > 0);
  const statusBars = ['confirmed', 'likely', 'unconfirmed']
    .map((k) => ({ label: k, value: vsum[k] || 0, color: STATUS_HEX[k] }))
    .filter((b) => b.value > 0);
  const km = mapFromFindings(findings, { confirmed: (f) => f.status === 'confirmed' });

  // The TOC is built from what the report actually contains, so it never
  // points at an empty section.
  const sections = [
    { id: 'summary', label: 'Executive summary', on: true },
    { id: 'coverage', label: 'Testing coverage', on: covTotal > 0 },
    { id: 'surface', label: 'Attack surface', on: tech && (assets.length > 0 || techs.length > 0) },
    { id: 'narrative', label: 'Attack narrative', on: chains.length > 0 },
    { id: 'findings', label: `Findings (${total})`, on: true },
    { id: 'retest', label: 'Retest comparison', on: true },
  ].filter((s) => s.on);

  function goto(id) {
    document.getElementById(id)?.scrollIntoView?.({ behavior: 'smooth', block: 'start' });
  }
  const toggle = (id) => setOpen((o) => o.includes(id) ? o.filter((x) => x !== id) : [...o, id]);
  const allOpen = findings.length > 0 && open.length >= findings.length;
  const toggleAll = () => setOpen(allOpen ? [] : findings.map((f) => f.id));

  async function writeNarrative() {
    if (!eng) return;
    setWriting(true); setNarrative(null);
    try {
      const r = await api.llm.report({
        title: `Penetration Test - ${eng.target_host || eng.target_url}`,
        scope: (eng.scope_hosts || []).join(', '),
      });
      setNarrative(r.markdown || '(empty)');
      goto('summary');
    } catch (e) {
      setNarrative(`Could not generate: ${e.message}`);
    } finally { setWriting(false); }
  }

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
      a.href = url; a.download = `syphax-${engId}.json`; a.click();
      URL.revokeObjectURL(url);
    } catch (e) { flash(`JSON export failed: ${e.message}`); }
  }

  return (
    <div className="page reports">
      <Notice kind="error" message={loadError} onRetry={() => setLoadError(null)} />
      <Notice kind="error" title="Could not load engagements"
              message={engError} onRetry={reloadEngagements} />

      <div className="rep-bar">
        <div className="rep-bar__l">
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
          <button className="btn btn--solid" onClick={writeNarrative} disabled={!engId || writing}>
            {writing ? 'Writing…' : 'LLM narrative'}
          </button>
          <span className="rep-formats__lbl">export</span>
          <button className="btn btn--muted" onClick={() => exportAs('md')} disabled={!engId}>MD</button>
          <button className="btn btn--muted" onClick={() => exportAs('print')} disabled={!engId}>PDF</button>
          <button className="btn btn--muted" onClick={exportJson} disabled={!engId}>JSON</button>
          <button className="btn btn--muted" onClick={() => exportAs('sarif')} disabled={!engId}>SARIF</button>
        </div>
      </div>

      {!eng ? (
        <div className="card"><div className="card__body"><div className="empty">Select an engagement to assemble its report.</div></div></div>
      ) : (
        <div className="rep-layout">
          <nav className="rep-toc" aria-label="Report sections">
            <div className="rep-toc__t">Contents</div>
            {sections.map((s) => (
              <button key={s.id} className="rep-toc__link" onClick={() => goto(s.id)}>{s.label}</button>
            ))}
            <div className="rep-toc__foot mono">{tech ? 'technical' : 'executive'} report</div>
          </nav>

          <div className="doc">
            <div className="doc__brand"><span className="doc__wm">syphax</span><span className="doc__cls">confidential</span></div>
            <h1 className="doc__title">Web Application Penetration Test</h1>
            <div className="doc__sub">{eng.target_url}</div>

            {/* At-a-glance figures - the numbers a reader wants before any prose. */}
            <div className="rep-kpis">
              <div className="rep-kpi"><div className="rep-kpi__v">{total}</div><div className="rep-kpi__l">findings</div></div>
              <div className="rep-kpi rep-kpi--crit"><div className="rep-kpi__v">{dist.critical || 0}</div><div className="rep-kpi__l">critical</div></div>
              <div className="rep-kpi rep-kpi--high"><div className="rep-kpi__v">{dist.high || 0}</div><div className="rep-kpi__l">high</div></div>
              <div className="rep-kpi rep-kpi--ok"><div className="rep-kpi__v">{confirmed}</div><div className="rep-kpi__l">confirmed</div></div>
              {covTotal > 0 && <div className="rep-kpi"><div className="rep-kpi__v">{covPct}<small>%</small></div><div className="rep-kpi__l">coverage</div></div>}
            </div>

            <section id="summary" className="sec">
              <div className="sec__h">Executive summary</div>
              <dl className="meta-grid">
                <dt>Target</dt><dd>{eng.target_url}</dd>
                <dt>Scope</dt><dd>{(eng.scope_hosts || []).join(', ')}</dd>
                <dt>Authorized via</dt><dd>{eng.verification_method || '-'}</dd>
                <dt>Engagement</dt><dd>{eng.id}</dd>
              </dl>
              <p style={{ marginTop: 16 }}>The autonomous assessment of <strong>{eng.target_url}</strong> identified <strong>{total} validated finding(s)</strong>, including <strong>{dist.critical || 0} critical</strong> and <strong>{dist.high || 0} high</strong>-severity issues. <strong>{confirmed}</strong> were confirmed with a safe, read-only proof.</p>

              {km.categories.length > 0 && (
                <div style={{ marginTop: 18 }}>
                  <KnowledgeMap categories={km.categories} confidence={km.confidence}
                                title="Findings map" subtitle={`${total} finding(s) by category · click to jump to findings`}
                                onSelect={() => goto('findings')} />
                </div>
              )}

              <div className="viz-row" style={{ marginTop: 18 }}>
                <div className="viz">
                  <div className="viz__h">Severity mix</div>
                  <div className="viz__body">
                    {total > 0 ? (
                      <>
                        <Donut segments={sevSegments} centerLabel="findings" />
                        <Legend segments={sevSegments} />
                      </>
                    ) : <div className="empty">No findings.</div>}
                  </div>
                </div>

                <div className="viz">
                  <div className="viz__h">Testing coverage</div>
                  <div className="viz__body" style={{ flexDirection: 'column' }}>
                    <Radar values={radarValues} axes={COV_AXES} />
                    <div className="radar-axes">
                      {COV_AXES.map((a, i) => <span key={a}>{a} <b>{radarValues[i]}%</b></span>)}
                    </div>
                  </div>
                </div>

                <div className="viz">
                  <div className="viz__h">Validation status</div>
                  <div className="viz__body" style={{ width: '100%' }}>
                    {statusBars.length > 0
                      ? <Histogram data={statusBars} />
                      : <div className="empty">Nothing validated yet.</div>}
                  </div>
                </div>
              </div>

              {/* Keep the compact severity bars too - a quick left-to-right read
                  under the charts. */}
              <div className="sevdist" style={{ marginTop: 16 }}>
                {SEV_BARS.map((s) => (
                  <div key={s} className="sevdist__row">
                    <span className="sevdist__l" style={{ color: SEV_HEX[s] }}>{s}</span>
                    <span className="sevdist__bar"><span className="sevdist__fill" style={{ width: ((dist[s] || 0) / maxd * 100) + '%', background: SEV_HEX[s] }}></span></span>
                    <span className="sevdist__n">{dist[s] || 0}</span>
                  </div>
                ))}
              </div>

              {/* The LLM draft lives inside the summary where its prose belongs,
                  but stays visibly a draft (mono, badge) so nobody ships it to a
                  client unread. */}
              {narrative && (
                <div className="rep-draft">
                  <div className="rep-draft__h"><span className="rep-draft__badge">LLM draft</span><span className="rep-draft__note">review and edit before sending</span></div>
                  <pre className="rep-narrative">{narrative}</pre>
                </div>
              )}
            </section>

            {covTotal > 0 && (
              <section id="coverage" className="sec">
                <div className="sec__h">Testing coverage</div>
                <p>{covDone} of {covTotal} planned checks completed against in-scope assets.</p>
                <div className="covline">
                  <span className="covline__n">completed</span>
                  <span className="covline__bar"><span className="covline__fill" style={{ width: covPct + '%' }}></span></span>
                  <span className="covline__pct">{covPct}%</span>
                </div>
                <div className="rep-chips" style={{ marginTop: 10 }}>
                  {Object.entries(cov).sort((a, b) => b[1] - a[1]).map(([k, n]) => (
                    <span key={k} className="map-chip">{k} · {n}</span>
                  ))}
                </div>
              </section>
            )}

            {tech && (assets.length > 0 || techs.length > 0) && (
              <section id="surface" className="sec">
                <div className="sec__h">Attack surface</div>
                {techs.length > 0 && (
                  <><div className="rfind__lbl">Technologies</div>
                    <div className="rep-chips">{techs.map((t) => <span key={t} className="map-chip">{t}</span>)}</div></>
                )}
                {assets.length > 0 && (
                  <><div className="rfind__lbl">Assets ({assets.length})</div>
                    <div className="rep-assets">
                      {assets.slice(0, 40).map((a, i) => (
                        <div key={i} className="rep-asset">
                          <span className={'rep-asset__k rep-asset__k--' + a.kind}>{a.kind}</span>
                          <span className="rep-asset__v mono">{a.value}</span>
                          {a.has_params && <span className="rep-asset__t">params</span>}
                          {a.is_https && <span className="rep-asset__t">https</span>}
                        </div>
                      ))}
                    </div>
                    {assets.length > 40 && <div className="rfind__txt">…and {assets.length - 40} more.</div>}
                  </>
                )}
              </section>
            )}

            {chains.length > 0 && (
              <section id="narrative" className="sec">
                <div className="sec__h">Attack narrative (kill-chain)</div>
                {chains.map((c) => (
                  <div key={c.id} className="rep-chain">
                    <div className="rep-chain__t">{c.title}{c.severity ? <span className={'sev sev--' + c.severity} style={{ marginLeft: 8 }}>{c.severity}</span> : null}</div>
                    {c.summary && <p className="rfind__txt" style={{ margin: '4px 0 8px' }}>{c.summary}</p>}
                    <div className="kc">
                      {(c.steps || []).map((st, i) => (
                        <span key={i}>{i > 0 ? <span className="kc__arrow">-&gt;</span> : null}<span className="kc__node">{st.action}</span></span>
                      ))}
                    </div>
                  </div>
                ))}
              </section>
            )}

            <section id="findings" className="sec">
              <div className="sec__h sec__h--row">
                <span>Findings ({findings.length})</span>
                {tech && findings.length > 0 && (
                  <button className="rep-linkbtn" onClick={toggleAll}>{allOpen ? 'Collapse all' : 'Expand all'}</button>
                )}
              </div>

              {findings.length === 0 && <div className="empty">No validated findings yet.</div>}

              {/* Executive: a compact risk register, no request/response noise.
                  Technical: the full expandable entry with evidence and PoC. */}
              {!tech && findings.length > 0 && (
                <table className="rep-reg">
                  <thead><tr><th>Severity</th><th>Finding</th><th>Class</th><th>Status</th></tr></thead>
                  <tbody>
                    {findings.map((f) => (
                      <tr key={f.id}>
                        <td><span className={'sev sev--' + f.severity}>{f.severity}</span></td>
                        <td>{f.title}</td>
                        <td className="mono" style={{ color: 'var(--text-faint)' }}>{f.vuln_class}</td>
                        <td><span className={'vstatus vstatus--' + f.status}>{f.status}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}

              {tech && findings.map((f) => {
                const isOpen = open.includes(f.id);
                return (
                  <div key={f.id} className={'rfind rfind--' + f.severity}>
                    <div className="rfind__head" onClick={() => toggle(f.id)}>
                      <span className={'sev sev--' + f.severity}>{f.severity}</span>
                      <span className="rfind__title">{f.title}</span>
                      {f.proven && <span className="rfind__proven" title="Confirmed by an oracle, not a scanner pattern">proven</span>}
                      <span className={'vstatus vstatus--' + f.status} style={{ marginLeft: 'auto' }}>{f.status}</span>
                      <span className="rfind__caret">{isOpen ? '−' : '+'}</span>
                    </div>
                    {isOpen && (
                      <div className="rfind__body">
                        <div className="rfind__target">{f.target}</div>
                        <div className="rfind__lbl">Class / tool</div>
                        <div className="rfind__txt">{f.vuln_class} &middot; {f.tool}{f.method ? ' · ' + f.method : ''}{f.category ? ' · ' + f.category : ''}</div>
                        {f.corroboration && <><div className="rfind__lbl">Corroboration</div><div className="rfind__txt">{f.corroboration}</div></>}
                        {f.evidence && <><div className="rfind__lbl">Evidence</div><pre className="rfind__pre">{f.evidence}</pre></>}
                        {f.poc && <><div className="rfind__lbl">Proof of concept</div><pre className="rfind__pre poc">{f.poc}</pre></>}
                      </div>
                    )}
                  </div>
                );
              })}
            </section>

            <section id="retest" className="sec">
              <div className="sec__h sec__h--row">
                <span>Retest comparison</span>
                {diff.data && <span className="mono" style={{ fontSize: 11, color: 'var(--text-faint)' }}>{diff.data.counts.fixed} fixed · {diff.data.counts.new} new</span>}
              </div>
              <p className="rfind__txt">Compare this engagement with an earlier one on the same target: what the client fixed, what came back, and what is new.</p>
              <div className="row" style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginTop: 8 }}>
                <div className="select-box">
                  <select id="diff-against" className="select" value={against} onChange={(e) => setAgainst(e.target.value)}>
                    <option value="">earlier engagement…</option>
                    {engagements.filter((e) => e.id !== engId).map((e) => (
                      <option key={e.id} value={e.id}>{e.target_host || e.target_url} — {e.id.slice(0, 8)}</option>
                    ))}
                  </select>
                </div>
                <button className="btn" disabled={!against || diff.loading} onClick={() => diff.reload()}>
                  {diff.loading ? 'Comparing…' : 'Compare'}
                </button>
              </div>
              {(diff.data || diff.error) && (
                <div style={{ marginTop: 12 }}>
                  <Async loading={diff.loading} error={diff.error} data={diff.data} onRetry={() => diff.reload()} empty="Nothing to compare.">
                    <>
                      <p className="rfind__txt">{diff.data?.summary}</p>
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
            </section>
          </div>
        </div>
      )}
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
