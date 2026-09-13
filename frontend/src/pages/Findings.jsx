import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api.js';
import { useEngagements } from '../lib/useApi.js';

// Sentinel for the opt-in cross-engagement view; '' would be indistinguishable
// from "nothing selected yet", which is what made aggregating the default.
const ALL_ENGAGEMENTS = '__all__';
import { Notice } from '../components/ui.jsx';

const SEVS = ['critical', 'high', 'medium', 'low'];
const STATUSES = ['new', 'triaged', 'confirmed', 'reported', 'false_positive'];
const CVSS_CLASS = (s) => s >= 9 ? 'c' : s >= 7 ? 'h' : s >= 4 ? 'm' : 'l';

function ago(ts) {
  if (!ts) return '-';
  const sec = Math.max(0, Date.now() / 1000 - ts);
  if (sec < 90) return Math.round(sec) + 's ago';
  if (sec < 5400) return Math.round(sec / 60) + 'm ago';
  if (sec < 86400) return Math.round(sec / 3600) + 'h ago';
  return Math.round(sec / 86400) + 'd ago';
}

export default function Findings() {
  const [rows, setRows] = useState([]);
  const [sevFilter, setSevFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [q, setQ] = useState('');
  const [sel, setSel] = useState(null);
  const [toast, setToast] = useState(null);
  const [loadError, setLoadError] = useState(null);
  const { engagements, engId, setEngId } = useEngagements();
  const [chains, setChains] = useState([]);
  const flash = (m) => { setToast(m); setTimeout(() => setToast(null), 2000); };


  // Segmented by default. Aggregating across engagements is useful for triage
  // but wrong when reading one target: it merged a second engagement's
  // findings into the first, so a stale exposed .git from yesterday sat next
  // to today's scan. ALL is now an explicit choice, not the landing state.
  const aggregate = engId === ALL_ENGAGEMENTS;
  const load = useCallback(async () => {
    try {
      if (engId && !aggregate) {
        const [f, c] = await Promise.all([
          api.engagements.findings(engId), api.engagements.chains(engId),
        ]);
        let items = f.items || [];
        if (sevFilter !== 'all') items = items.filter((x) => x.severity === sevFilter);
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
      // Aggregate view: no kill-chain belongs to "all engagements".
      setChains([]);
      const r = await api.findings.list({
        severity: sevFilter !== 'all' ? sevFilter : undefined,
        status: statusFilter !== 'all' ? statusFilter : undefined,
        q: q || undefined,
      });
      setRows(r.items || []);
    } catch (e) { console.error('findings load failed', e); }
  }, [sevFilter, statusFilter, q, engId, aggregate]);
  useEffect(() => { load(); }, [load]);

  const counts = SEVS.reduce((o, s) => (o[s] = rows.filter((f) => f.severity === s).length, o), {});
  const f = rows.find((x) => x.id === sel) || (rows.length && sevFilter === 'all' && statusFilter === 'all' && !q ? null : null);

  async function setStatus(id, status, msg) {
    try { await api.findings.setStatus(id, status); flash(msg); await load(); } catch (e) { flash(e.message); }
  }
  async function retest(id) {
    flash('Re-testing...');
    try { const r = await api.findings.retest(id); flash(r.status === 'false_positive' ? 'Retest: no longer reproduced' : 'Retest complete'); await load(); } catch (e) { flash(e.message); }
  }

  return (
    <div className="page">
      <Notice kind="error" message={loadError} />
      <div className="metrics" style={{ gridTemplateColumns: 'repeat(4,1fr)' }}>
        <div className="metric metric--alert"><div className="metric__l">Critical</div><div className="metric__v">{counts.critical}</div></div>
        <div className="metric"><div className="metric__l" style={{ color: 'var(--severity-high)' }}>High</div><div className="metric__v" style={{ color: 'var(--severity-high)' }}>{counts.high}</div></div>
        <div className="metric"><div className="metric__l" style={{ color: 'var(--severity-medium)' }}>Medium</div><div className="metric__v" style={{ color: 'var(--severity-medium)' }}>{counts.medium}</div></div>
        <div className="metric"><div className="metric__l">Low</div><div className="metric__v">{counts.low}</div></div>
      </div>

      <div className="filters">
        <div className="filter-seg">
          <button className={sevFilter === 'all' ? 'on' : ''} onClick={() => setSevFilter('all')}>All sev</button>
          {SEVS.map((s) => <button key={s} className={(sevFilter === s ? 'on sev-' + s[0] : '')} onClick={() => setSevFilter(s)}>{s}</button>)}
        </div>
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
        <input className="filter-search" placeholder="search title / target / class..." value={q} onChange={(e) => setQ(e.target.value)} />
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
          <div className="card__head"><span className="card__title">Findings <span style={{ color: 'var(--text-faint)' }}>({rows.length})</span></span><span className="card__meta">{aggregate ? 'deduped across engagements' : 'this engagement only'}</span></div>
          <div className="tbl-scroll">
            <table className="tbl">
              <thead><tr><th>Sev</th><th>CVSS</th><th>Title</th><th>Target</th><th>Status</th><th>Eng.</th><th></th></tr></thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id} className={'clickable' + (r.id === sel ? ' selected' : '')} onClick={() => setSel(r.id)}>
                    <td><span className={'sev sev--' + r.severity}>{r.severity}</span></td>
                    <td><span className={'cvss cvss--' + CVSS_CLASS(r.cvss)}>{(r.cvss || 0).toFixed(1)}</span></td>
                    <td className="col-title">{r.title}{r.dup > 1 ? <span className="dedup"> &middot; <b>{r.dup}x</b></span> : null}</td>
                    <td className="mono truncate" style={{ maxWidth: 180, color: 'var(--text-secondary)' }} title={r.target}>{r.target}</td>
                    <td><span className={'status-pill ' + r.status}>{(r.status || 'new').replace('_', ' ')}</span></td>
                    <td className="mono" style={{ color: 'var(--text-faint)', fontSize: 11 }}>{r.engagement}</td>
                    <td className="mono" style={{ color: 'var(--text-faint)', fontSize: 11 }}>{ago(r.last_seen)}</td>
                  </tr>
                ))}
                {rows.length === 0 && <tr><td colSpan={7}><div className="empty-detail">No findings match.</div></td></tr>}
              </tbody>
            </table>
          </div>
        </div>

        <div className="card detail">
          {!f ? <div className="empty-detail">Select a finding.</div> : (
            <div className="card__body">
              <div className="detail__row"><span className={'sev sev--' + f.severity}>{f.severity}</span><span className={'cvss cvss--' + CVSS_CLASS(f.cvss)}>CVSS {(f.cvss || 0).toFixed(1)}</span><span className={'status-pill ' + f.status}>{(f.status || 'new').replace('_', ' ')}</span></div>
              <h2 className="detail__title">{f.title}</h2>
              <div className="detail__target">{f.target}</div>
              {f.desc && <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.55, margin: '0 0 4px' }}>{f.desc}</p>}
              <dl className="detail__meta">
                <dt>Class</dt><dd>{f.cls}</dd>
                <dt>Tool</dt><dd>{f.tool}</dd>
                <dt>Engagement</dt><dd>{f.engagement}</dd>
                <dt>Occurrences</dt><dd>{f.dup}</dd>
                <dt>Last seen</dt><dd>{ago(f.last_seen)}</dd>
              </dl>
              {f.evidence && <><div className="detail__block-t">Evidence</div><div className="detail__pre">{f.evidence}</div></>}
              {f.poc && <><div className="detail__block-t">Proof of concept</div><div className="detail__pre poc">{f.poc}</div></>}
              {f.req && <><div className="detail__block-t">Request</div><div className="detail__pre">{f.req}</div></>}
              {f.resp && <><div className="detail__block-t">Response</div><div className="detail__pre">{f.resp}</div></>}
              <div className="detail__actions">
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
