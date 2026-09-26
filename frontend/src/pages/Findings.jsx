import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../lib/api.js';
import { useEngagements } from '../lib/useApi.js';
import { Notice } from '../components/ui.jsx';
import KnowledgeMap from '../components/KnowledgeMap.jsx';
import { mapFromFindings } from '../lib/knowledgeMap.js';

// Sentinel for the opt-in cross-engagement view; '' would be indistinguishable
// from "nothing selected yet", which is what made aggregating the default.
const ALL_ENGAGEMENTS = '__all__';

const SEVS = ['critical', 'high', 'medium', 'low'];
const STATUSES = ['new', 'triaged', 'confirmed', 'reported', 'false_positive'];
const CVSS_CLASS = (s) => (s >= 9 ? 'c' : s >= 7 ? 'h' : s >= 4 ? 'm' : 'l');

function ago(ts) {
  if (!ts) return '-';
  const sec = Math.max(0, Date.now() / 1000 - ts);
  if (sec < 90) return Math.round(sec) + 's ago';
  if (sec < 5400) return Math.round(sec / 60) + 'm ago';
  if (sec < 86400) return Math.round(sec / 3600) + 'h ago';
  return Math.round(sec / 86400) + 'd ago';
}

// A collapsible evidence block, so a page of a captured response does not push
// the actions off-screen. Open by default for the short, decisive ones.
function Block({ title, children, poc = false, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="fdrawer">
      <button type="button" className="fdrawer__h" onClick={() => setOpen((o) => !o)}>
        <span className="fdrawer__caret">{open ? '▾' : '▸'}</span>{title}
      </button>
      {open && <div className={'detail__pre' + (poc ? ' poc' : '')}>{children}</div>}
    </div>
  );
}

export default function Findings() {
  const [rows, setRows] = useState([]);
  const [sevFilter, setSevFilter] = useState('all');
  const [catFilter, setCatFilter] = useState(null);
  const [statusFilter, setStatusFilter] = useState('all');
  const [q, setQ] = useState('');
  const [sel, setSel] = useState(null);
  const [toast, setToast] = useState(null);
  const [loadError, setLoadError] = useState(null);
  const { engagements, engId, setEngId } = useEngagements();
  const [chains, setChains] = useState([]);
  const searchRef = useRef(null);
  const flash = (m) => { setToast(m); setTimeout(() => setToast(null), 2000); };

  // Segmented by default. Aggregating across engagements is useful for triage
  // but wrong when reading one target: it merged a second engagement's findings
  // into the first. ALL is an explicit choice, not the landing state.
  const aggregate = engId === ALL_ENGAGEMENTS;
  const load = useCallback(async () => {
    try {
      if (engId && !aggregate) {
        const [f, c] = await Promise.all([
          api.engagements.findings(engId), api.engagements.chains(engId),
        ]);
        let items = f.items || [];
        if (statusFilter !== 'all') items = items.filter((x) => x.status === statusFilter);
        if (q) {
          const needle = q.toLowerCase();
          items = items.filter((x) => `${x.title} ${x.target} ${x.vuln_class}`
            .toLowerCase().includes(needle));
        }
        setRows(items);
        setChains(c.items || []);
        return;
      }
      setChains([]);   // no kill-chain belongs to "all engagements"
      const r = await api.findings.list({
        status: statusFilter !== 'all' ? statusFilter : undefined,
        q: q || undefined,
      });
      setRows(r.items || []);
    } catch (e) { setLoadError(e.message); }
  }, [statusFilter, q, engId, aggregate]);
  useEffect(() => { load(); }, [load]);

  // Counts are over the full (status/search-filtered) set, so the tiles keep
  // their meaning while one severity is selected - the severity filter is a
  // client-side view, not another query.
  const counts = SEVS.reduce((o, s) => ((o[s] = rows.filter((f) => f.severity === s).length), o), {});
  const km = mapFromFindings(rows);
  const visible = rows.filter((r) =>
    (sevFilter === 'all' || r.severity === sevFilter)
    && (!catFilter || (r.category || 'other') === catFilter));
  const f = rows.find((x) => x.id === sel) || null;

  // ↑/↓ moves the selection through the list, so triage is a keyboard loop and
  // not a mouse hunt. Ignored while typing in the search box.
  useEffect(() => {
    const onKey = (e) => {
      if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
      if (document.activeElement === searchRef.current) return;
      if (!visible.length) return;
      e.preventDefault();
      const i = visible.findIndex((r) => r.id === sel);
      const next = e.key === 'ArrowDown'
        ? Math.min((i < 0 ? -1 : i) + 1, visible.length - 1)
        : Math.max((i < 0 ? visible.length : i) - 1, 0);
      setSel(visible[next].id);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [visible, sel]);

  async function setStatus(id, status, msg) {
    try { await api.findings.setStatus(id, status); flash(msg); await load(); } catch (e) { flash(e.message); }
  }
  async function retest(id) {
    flash('Re-testing...');
    try {
      const r = await api.findings.retest(id);
      flash(r.status === 'false_positive' ? 'Retest: no longer reproduced' : 'Retest complete');
      await load();
    } catch (e) { flash(e.message); }
  }

  const sevTile = (key, label) => {
    const on = sevFilter === key;
    const n = key === 'all' ? rows.length : counts[key];
    return (
      <button key={key}
              className={'fkpi fkpi--' + key + (on ? ' fkpi--on' : '')}
              aria-pressed={on}
              onClick={() => setSevFilter(on && key !== 'all' ? 'all' : key)}>
        <span className="fkpi__v">{n}</span>
        <span className="fkpi__l">{label}</span>
      </button>
    );
  };

  return (
    <div className="page fnd">
      <Notice kind="error" message={loadError} />

      {km.categories.length > 0 && (
        <KnowledgeMap categories={km.categories} confidence={km.confidence}
                      title="Findings map"
                      subtitle={catFilter
                        ? `filtering ${km.categories.find((c) => c.key === catFilter)?.label || catFilter} · click again to clear`
                        : `${rows.length} finding(s) · ${km.confidence}% confirmed · click a category to filter`}
                      activeKey={catFilter || km.categories[0].key}
                      metricLabel="confirmed"
                      onSelect={(k) => setCatFilter((cur) => (cur === k ? null : k))} />
      )}

      {/* Severity is the primary axis of triage, so the counts ARE the filter -
          click a tile to narrow, click it again to clear. */}
      <div className="fkpis">
        {sevTile('all', 'All')}
        {sevTile('critical', 'Critical')}
        {sevTile('high', 'High')}
        {sevTile('medium', 'Medium')}
        {sevTile('low', 'Low')}
      </div>

      <div className="filters">
        <div className="filter-seg">
          <button className={statusFilter === 'all' ? 'on' : ''} onClick={() => setStatusFilter('all')}>All status</button>
          {STATUSES.map((s) => <button key={s} className={statusFilter === s ? 'on' : ''} onClick={() => setStatusFilter(s)}>{s.replace('_', ' ')}</button>)}
        </div>
        <div className="select-box">
          <select className="select" value={engId} onChange={(e) => setEngId(e.target.value)}>
            <option value="__all__">All engagements (deduped)</option>
            {engagements.map((e) => (
              <option key={e.id} value={e.id}>{e.target_host || e.target_url}</option>
            ))}
          </select>
        </div>
        <input ref={searchRef} className="filter-search" placeholder="search title / target / class…"
               value={q} onChange={(e) => setQ(e.target.value)} />
      </div>

      {chains.length > 0 && (
        <div className="card">
          <div className="card__head">
            <span className="card__title">Kill-chains</span>
            <span className="card__meta">{chains.length} for this engagement</span>
          </div>
          <div className="card__body">
            {chains.map((c) => (
              <div key={c.id} className="fnd-chain">
                <span className={'sev sev--' + (c.severity || 'info')}>{c.severity}</span>
                <span className="fnd-chain__t">{c.title}</span>
                <span className="fnd-chain__s">{(c.steps || c.steps_json || []).length || ''} step(s)</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="layout">
        <div className="card">
          <div className="card__head">
            <span className="card__title">Findings <span style={{ color: 'var(--text-faint)' }}>({visible.length})</span></span>
            <span className="card__meta">{aggregate ? 'deduped across engagements' : 'this engagement only'}</span>
          </div>
          <div className="tbl-scroll">
            <table className="tbl fnd-tbl">
              <thead><tr><th>Sev</th><th>CVSS</th><th>Title</th><th>Target</th><th>Status</th><th>Eng.</th><th>Seen</th></tr></thead>
              <tbody>
                {visible.map((r) => (
                  <tr key={r.id}
                      className={'clickable fnd-row fnd-row--' + r.severity + (r.id === sel ? ' selected' : '')}
                      onClick={() => setSel(r.id)}>
                    <td><span className={'sev sev--' + r.severity}>{r.severity}</span></td>
                    <td><span className={'cvss cvss--' + CVSS_CLASS(r.cvss)}>{(r.cvss || 0).toFixed(1)}</span></td>
                    <td className="col-title">{r.title}{r.dup > 1 ? <span className="dedup"> · <b>{r.dup}×</b></span> : null}</td>
                    <td className="mono truncate" style={{ maxWidth: 180, color: 'var(--text-secondary)' }} title={r.target}>{r.target}</td>
                    <td><span className={'status-pill ' + r.status}>{(r.status || 'new').replace('_', ' ')}</span></td>
                    <td className="mono" style={{ color: 'var(--text-faint)', fontSize: 11 }}>{r.engagement}</td>
                    <td className="mono" style={{ color: 'var(--text-faint)', fontSize: 11 }}>{ago(r.last_seen)}</td>
                  </tr>
                ))}
                {visible.length === 0 && <tr><td colSpan={7}><div className="empty-detail">No findings match.</div></td></tr>}
              </tbody>
            </table>
          </div>
          {visible.length > 0 && <div className="fnd-hint">↑ ↓ to move · click a row to inspect</div>}
        </div>

        <div className="card detail">
          {!f ? (
            <div className="empty-detail">
              {rows.length ? 'Select a finding, or press ↓.' : 'No finding selected.'}
            </div>
          ) : (
            <div className="card__body fdetail">
              <div className="fdetail__head">
                <div className="detail__row">
                  <span className={'sev sev--' + f.severity}>{f.severity}</span>
                  <span className={'cvss cvss--' + CVSS_CLASS(f.cvss)}>CVSS {(f.cvss || 0).toFixed(1)}</span>
                  <span className={'status-pill ' + f.status}>{(f.status || 'new').replace('_', ' ')}</span>
                </div>
                <h2 className="detail__title">{f.title}</h2>
                <div className="detail__target">{f.target}</div>
              </div>

              <div className="fdetail__scroll">
                {f.desc && <p className="fdetail__desc">{f.desc}</p>}
                <dl className="detail__meta">
                  <dt>Class</dt><dd>{f.cls}</dd>
                  <dt>Tool</dt><dd>{f.tool}</dd>
                  <dt>Engagement</dt><dd>{f.engagement}</dd>
                  <dt>Occurrences</dt><dd>{f.dup}</dd>
                  <dt>Last seen</dt><dd>{ago(f.last_seen)}</dd>
                </dl>

                {f.proof_replay && (
                  <div className={'shadow ' + (f.proof_replay.outcome === 'held' ? 'shadow--agree'
                    : f.proof_replay.outcome === 'did_not_hold' ? 'shadow--diff' : '')}>
                    <div className="shadow__h">Live proof replay</div>
                    <div className="shadow__row">
                      {f.proof_replay.outcome === 'held' && <b>confirmed by a read-only replay</b>}
                      {f.proof_replay.outcome === 'did_not_hold' && <b>the model claimed this; a replay refuted it</b>}
                      {!['held', 'did_not_hold'].includes(f.proof_replay.outcome) && <span>{f.proof_replay.outcome}: {f.proof_replay.detail}</span>}
                    </div>
                    {f.proof_replay.request && <div className="shadow__reason mono">{f.proof_replay.request}</div>}
                    <div className="shadow__note">
                      A finding reaches &ldquo;confirmed&rdquo; only when a live replay finds the
                      observable the judge named — the model never confirms on its own.
                    </div>
                  </div>
                )}
                {f.shadow_judge && (
                  <div className={'shadow ' + (f.shadow_judge.agreement === 'agree' ? 'shadow--agree' : 'shadow--diff')}>
                    <div className="shadow__h">
                      Second opinion ({f.shadow_judge.backend})
                      <span className="shadow__tag">
                        {f.shadow_judge.agreement === 'agree' ? 'agreed'
                          : f.shadow_judge.agreement === 'shadow_looser'
                            ? 'would ship this (looser)' : 'would drop this (stricter)'}
                      </span>
                    </div>
                    <div className="shadow__row">
                      <span>shipped verdict</span><b>{f.shadow_judge.base?.status}</b>
                      <span>· {f.shadow_judge.backend} said</span><b>{f.shadow_judge.shadow?.status}</b>
                      {f.shadow_judge.shadow?.confidence != null && (
                        <span className="shadow__conf">p={f.shadow_judge.shadow.confidence}</span>
                      )}
                    </div>
                    {f.shadow_judge.shadow?.reason && <div className="shadow__reason">{f.shadow_judge.shadow.reason}</div>}
                    <div className="shadow__note">Recorded for comparison only — it did not affect the verdict above.</div>
                  </div>
                )}

                {f.evidence && <Block title="Evidence">{f.evidence}</Block>}
                {f.poc && <Block title="Proof of concept" poc>{f.poc}</Block>}
                {f.req && <Block title="Request" defaultOpen={false}>{f.req}</Block>}
                {f.resp && <Block title="Response" defaultOpen={false}>{f.resp}</Block>}
              </div>

              <div className="detail__actions fdetail__actions">
                <button className="btn btn--solid" onClick={() => retest(f.id)}>Retest</button>
                <a className="btn" href={api.findings.exportUrl(f.id)} target="_blank" rel="noreferrer">Export H1</a>
                <button className="btn btn--muted" onClick={() => setStatus(f.id, 'reported', 'Marked as reported')}>Mark reported</button>
                <button className="btn btn--danger" onClick={() => setStatus(f.id, 'false_positive', 'Marked false positive')}>False positive</button>
              </div>
            </div>
          )}
        </div>
      </div>
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
