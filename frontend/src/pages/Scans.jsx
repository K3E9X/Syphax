import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api.js';

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
function Sev({ s }) { return <span className={'sev sev--' + s}>{s}</span>; }

// The LLM explanation summarizes attacker-influenced scan output / target
// responses, so it must be HTML-escaped before we apply the tiny **bold**/\n
// formatting. Escape FIRST, then introduce only the markup we control.
function renderExplain(md) {
  const esc = String(md)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  return esc.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>').replace(/\n/g, '<br/>');
}

export default function Scans() {
  const [tools, setTools] = useState([]);
  const [engagements, setEngagements] = useState([]);
  const [form, setForm] = useState({ engagement_id: '', tool: 'nuclei', target: '', options: '' });
  const [jobs, setJobs] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [detail, setDetail] = useState(null);
  const [tab, setTab] = useState('findings');
  const [error, setError] = useState(null);
  const [explain, setExplain] = useState({ loading: false, md: null });
  const set = (p) => setForm((f) => ({ ...f, ...p }));

  const loadJobs = useCallback(async () => {
    try { const r = await api.scans.list(); setJobs(r.items || []); } catch (e) { setError(e.message); }
  }, []);

  useEffect(() => {
    api.scans.tools().then((t) => setTools(Array.isArray(t) ? t : []))
      .catch((e) => setError(e.message));
    api.engagements.list().then((r) => {
      const items = r.items || [];
      setEngagements(items);
      if (items.length) set({ engagement_id: items[0].id });
    }).catch((e) => setError(e.message));
    loadJobs();
  }, [loadJobs]);

  useEffect(() => {
    const t = setInterval(loadJobs, 4000);
    return () => clearInterval(t);
  }, [loadJobs]);

  const avail = tools.filter((t) => t.available).length;

  async function onSubmit(e) {
    e.preventDefault();
    setError(null);
    if (!form.tool || !form.target) { setError('Tool and target are required.'); return; }
    if (!form.engagement_id) { setError('Select an authorized engagement (scope gate).'); return; }
    try {
      const job = await api.scans.submit({
        tool: form.tool, target: form.target,
        options: form.options.split(' ').filter(Boolean),
        engagement_id: form.engagement_id,
      });
      set({ target: '' });
      await loadJobs();
      if (job?.id) select(job.id);
    } catch (err) { setError(err.message); }
  }

  async function select(id) {
    setSelectedId(id); setTab('findings'); setExplain({ loading: false, md: null }); setDetail(null);
    try { setDetail(await api.scans.get(id)); } catch (e) { setError(e.message); }
  }
  async function cancelJob(id) { try { await api.scans.cancel(id); await loadJobs(); select(id); } catch (e) { setError(e.message); } }
  async function deleteJob(id) { try { await api.scans.delete(id); setSelectedId(null); setDetail(null); await loadJobs(); } catch (e) { setError(e.message); } }
  async function doExplain() {
    setExplain({ loading: true, md: null });
    try { const r = await api.llm.explainJob(selectedId); setExplain({ loading: false, md: r.markdown || r.explanation || '(no explanation)' }); }
    catch (e) { setExplain({ loading: false, md: 'error: ' + e.message }); }
  }

  const job = detail || jobs.find((j) => j.id === selectedId);
  const dur = (ms) => ms != null ? (ms / 1000).toFixed(1) + 's' : '-';

  return (
    <div className="page">
      <div className="card">
        <div className="card__head"><span className="card__title">Launch a scan</span></div>
        <div className="card__body">
          <form className="scan-form" onSubmit={onSubmit}>
            <div className="field">
              <label className="field__label">Engagement</label>
              <div className="select-box">
                <select className="select" value={form.engagement_id} onChange={(e) => set({ engagement_id: e.target.value })}>
                  {engagements.length === 0 && <option value="">no engagements</option>}
                  {engagements.map((e) => <option key={e.id} value={e.id}>{e.target_host || e.target_url}</option>)}
                </select>
              </div>
            </div>
            <div className="field">
              <label className="field__label">Tool</label>
              <div className="select-box">
                <select className="select" value={form.tool} onChange={(e) => set({ tool: e.target.value })}>
                  {tools.map((t) => <option key={t.name} value={t.name} disabled={!t.available}>{t.name}{t.available ? '' : ' (not installed)'}</option>)}
                </select>
              </div>
            </div>
            <div className="field">
              <label className="field__label">Target URL or host</label>
              <input className="input" placeholder="https://example.com  (ffuf: use FUZZ)" value={form.target} onChange={(e) => set({ target: e.target.value })} />
            </div>
            <div className="field">
              <label className="field__label">Extra CLI options</label>
              <input className="input" placeholder="--level=3 --risk=3" value={form.options} onChange={(e) => set({ options: e.target.value })} />
            </div>
            <button type="submit" className="btn btn--solid">Run</button>
          </form>
          {error && <div className="scan-error">{error}</div>}
          <div className="scan-note">{avail}/{tools.length} tools available in this container.</div>
        </div>
      </div>

      <div className="card">
        <div className="card__head">
          <span className="card__title">Jobs <span style={{ color: 'var(--text-faint)' }}>({jobs.length})</span></span>
          <button className="btn btn--muted" onClick={loadJobs}>Refresh</button>
        </div>
        <div className="tbl-scroll">
          <table className="tbl">
            <thead><tr><th>ID</th><th>Tool</th><th>Target</th><th>Status</th><th>Findings</th><th>Duration</th></tr></thead>
            <tbody>
              {jobs.map((j) => (
                <tr key={j.id} className={'clickable' + (j.id === selectedId ? ' selected' : '')} onClick={() => select(j.id)}>
                  <td className="mono" style={{ color: 'var(--text-secondary)' }}>{j.id}</td>
                  <td className="mono">{j.tool}</td>
                  <td className="mono truncate" style={{ maxWidth: 240, color: 'var(--text-secondary)' }} title={j.target}>{j.target}</td>
                  <td><span className={'st st--' + j.status}>{j.status === 'running' ? <span className="blink">{j.status}</span> : j.status}</span></td>
                  <td><span className={'fcount ' + ((j.findings_count || 0) > 0 ? 'fcount--hit' : 'fcount--zero')}>{j.findings_count || 0}</span></td>
                  <td className="mono" style={{ color: 'var(--text-faint)' }}>{dur(j.duration_ms)}</td>
                </tr>
              ))}
              {jobs.length === 0 && <tr><td colSpan={6}><div className="empty">No jobs yet.</div></td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      {job && (
        <div className="card">
          <div className="card__head">
            <span className="card__title">Job inspector</span>
            <div style={{ display: 'flex', gap: 8 }}>
              {(job.status === 'running' || job.status === 'queued') && <button className="btn btn--muted" onClick={() => cancelJob(job.id)}>Cancel</button>}
              <button className="btn btn--danger" onClick={() => deleteJob(job.id)}>Delete</button>
              <button className="btn btn--muted" onClick={() => { setSelectedId(null); setDetail(null); }}>Close</button>
            </div>
          </div>

          <div className="inspect-head">
            <div className="inspect-head__main"><b>{job.tool}</b> {job.target}</div>
            <div className="inspect-head__meta">
              <span>id {job.id}</span><span className="sep">|</span>
              <span>status <span className={'st st--' + job.status}>{job.status}</span></span><span className="sep">|</span>
              <span>exit {job.exit_code ?? '-'}</span><span className="sep">|</span>
              <span>{dur(job.duration_ms)}</span>
              {(job.args || []).length ? <><span className="sep">|</span><span>args: {job.args.join(' ')}</span></> : null}
            </div>
            {job.error && <div style={{ marginTop: 6, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--severity-critical)' }}>error: {job.error}</div>}
          </div>

          <div style={{ padding: '12px 16px 0' }}>
            <div className="tabs" style={{ margin: 0 }}>
              <button className={'tab' + (tab === 'findings' ? ' tab--active' : '')} onClick={() => setTab('findings')}>Findings <span className="tab__count">{job.findings_count ?? (job.findings || []).length}</span></button>
              <button className={'tab' + (tab === 'stdout' ? ' tab--active' : '')} onClick={() => setTab('stdout')}>stdout</button>
              <button className={'tab' + (tab === 'stderr' ? ' tab--active' : '')} onClick={() => setTab('stderr')}>stderr</button>
            </div>
          </div>

          {tab === 'findings' && (
            <div className="findings-pad">
              {(job.findings || []).length === 0 ? <div className="io-empty" style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>No findings.</div> :
                job.findings.slice().sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)).map((f, i) => (
                  <div key={i} className="finding">
                    <div className="finding__top"><Sev s={f.severity} /><span className="mono truncate" style={{ fontSize: 11, color: 'var(--text-faint)', maxWidth: 280 }} title={f.target}>{f.target}</span></div>
                    <div className="finding__title">{f.title}</div>
                    {f.description && <div className="finding__desc">{f.description}</div>}
                    {f.evidence && <pre className="finding__poc">{f.evidence}</pre>}
                  </div>
                ))}
            </div>
          )}
          {tab === 'stdout' && <pre className="io-pre">{job.stdout_tail || <span className="io-empty">(empty)</span>}</pre>}
          {tab === 'stderr' && <pre className="io-pre">{job.stderr_tail || <span className="io-empty">(empty)</span>}</pre>}

          <div className="explain">
            <div className="explain__head">
              <span className="explain__title">LLM explanation</span>
              <button className="btn btn--muted" onClick={doExplain} disabled={explain.loading}>{explain.loading ? 'Generating...' : 'Explain findings'}</button>
            </div>
            {explain.md && <div className="explain__md" dangerouslySetInnerHTML={{ __html: renderExplain(explain.md) }}></div>}
          </div>
        </div>
      )}
    </div>
  );
}
