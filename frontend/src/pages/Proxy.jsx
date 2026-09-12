import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api.js';
import { Notice } from '../components/ui.jsx';

const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];
const fmtBytes = (n) => n == null ? '-' : n < 1024 ? n + ' B' : (n / 1024).toFixed(1) + ' KB';
const scClass = (c) => c >= 500 ? 'sc-5xx' : c >= 400 ? 'sc-4xx' : c >= 300 ? 'sc-3xx' : 'sc-2xx';
const timeOf = (ts) => ts ? new Date(ts * 1000).toLocaleTimeString('en-US', { hour12: false }) : '-';

export default function Proxy() {
  const [status, setStatus] = useState(null);
  const [loadError, setLoadError] = useState(null);
  const [hosts, setHosts] = useState([]);
  const [flows, setFlows] = useState([]);
  const [host, setHost] = useState('');
  const [method, setMethod] = useState('');
  const [search, setSearch] = useState('');
  const [sel, setSel] = useState(null);
  const [detail, setDetail] = useState(null);
  const [tab, setTab] = useState('request');
  const [engagementId, setEngagementId] = useState('');
  const [sugg, setSugg] = useState({ loading: false, items: null });
  const [toast, setToast] = useState(null);
  const flash = (m) => { setToast(m); setTimeout(() => setToast(null), 1800); };

  const loadFlows = useCallback(async () => {
    try {
      const r = await api.proxy.flows({ host: host || undefined, method: method || undefined, search: search || undefined, limit: 200 });
      setFlows(r.items || r || []);
    } catch (e) { flash(e.message); }
  }, [host, method, search]);

  useEffect(() => {
    api.proxy.status().then(setStatus).catch((e) => setLoadError(e.message));
    api.proxy.hosts().then((r) => setHosts((r.items || r || []).map((h) => h.host || h)))
      .catch((e) => setLoadError(e.message));
    api.engagements.list().then((r) => {
      const a = (r.items || []).find((e) => e.status === 'authorized') || (r.items || [])[0];
      if (a) setEngagementId(a.id);
    }).catch((e) => setLoadError(e.message));
  }, []);
  useEffect(() => { loadFlows(); }, [loadFlows]);

  async function select(id) {
    setSel(id); setTab('request'); setDetail(null); setSugg({ loading: false, items: null });
    try { setDetail(await api.proxy.flow(id)); } catch (e) { flash(e.message); }
  }
  async function clearFlows() { try { await api.proxy.clear(); await loadFlows(); flash('Cleared captured flows'); } catch (e) { flash(e.message); } }
  async function suggest() {
    if (!sel) return;
    setSugg({ loading: true, items: null });
    try {
      const r = await api.llm.suggestForFlow(sel);
      const items = r?.parsed?.suggested_scans || [];
      setSugg({ loading: false, items });
    } catch (e) { setSugg({ loading: false, items: [] }); flash(e.message); }
  }
  async function runScan(s) {
    try {
      await api.scans.submit({ tool: s.tool, target: s.target, options: s.options || [], engagement_id: engagementId, flow_id: sel });
      flash('Launched ' + s.tool + ' against ' + s.target);
    } catch (e) { flash(e.message); }
  }

  const f = detail;

  return (
    <div className="page">
      <Notice kind="error" message={loadError} />
      <div className="card">
        <div className="card__head"><span className="card__title">Proxy capture</span>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn--muted" onClick={loadFlows}>Refresh</button>
            <button className="btn btn--danger" onClick={clearFlows}>Clear</button>
          </div>
        </div>
        <div className="card__body">
          <div className="px-status">
            <div className="px-status__item"><div className="px-status__l">Status</div><div className="px-status__v"><span className="px-live">{status?.running ? 'listening' : 'unknown'}</span></div></div>
            <div className="px-status__item"><div className="px-status__l">Listen port</div><div className="px-status__v">{status?.port ?? 8080}</div></div>
            <div className="px-status__item"><div className="px-status__l">Flows captured</div><div className="px-status__v">{status?.flow_count ?? flows.length}</div></div>
            <div className="px-status__item"><div className="px-status__l">CA certificate</div><div className="px-status__v"><a href={api.proxy.caUrl()} target="_blank" rel="noreferrer">syphax-mitmproxy-ca.pem</a></div></div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card__body" style={{ paddingBottom: 14 }}>
          <div className="px-filters">
            <div className="select-box"><select className="select" value={host} onChange={(e) => setHost(e.target.value)}><option value="">All hosts</option>{hosts.map((h) => <option key={h} value={h}>{h}</option>)}</select></div>
            <div className="select-box"><select className="select" value={method} onChange={(e) => setMethod(e.target.value)}><option value="">All methods</option>{METHODS.map((m) => <option key={m} value={m}>{m}</option>)}</select></div>
            <input className="px-search" placeholder="filter URL..." value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
        </div>
        <div className="tbl-scroll">
          <table className="tbl">
            <thead><tr><th>Time</th><th>Method</th><th>Status</th><th>Host</th><th>Path</th><th>Size</th><th>ms</th></tr></thead>
            <tbody>
              {flows.map((fl) => (
                <tr key={fl.id} className={'clickable' + (fl.id === sel ? ' selected' : '')} onClick={() => select(fl.id)}>
                  <td className="mono" style={{ color: 'var(--text-faint)' }}>{timeOf(fl.timestamp)}</td>
                  <td><span className={'method m-' + fl.method}>{fl.method}</span></td>
                  <td><span className={'mono ' + scClass(fl.status_code || 0)}>{fl.status_code ?? '-'}</span></td>
                  <td className="mono" style={{ color: 'var(--text-secondary)' }}>{fl.host}</td>
                  <td className="mono truncate" style={{ maxWidth: 240 }} title={fl.path}>{fl.path}</td>
                  <td className="mono" style={{ color: 'var(--text-faint)' }}>{fmtBytes(fl.response_size)}</td>
                  <td className="mono" style={{ color: (fl.duration_ms || 0) > 1000 ? 'var(--severity-medium)' : 'var(--text-faint)' }}>{fl.duration_ms ?? '-'}</td>
                </tr>
              ))}
              {flows.length === 0 && <tr><td colSpan={7}><div className="empty">No flows captured yet. Browse the target through the proxy on :{status?.port ?? 8080}.</div></td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      {f && (
        <div className="card">
          <div className="card__head"><span className="card__title">Inspector</span><button className="btn btn--muted" onClick={() => { setSel(null); setDetail(null); }}>Close</button></div>
          <div className="px-head">
            <div className="px-head__main"><span className={'method m-' + f.method}>{f.method}</span> {f.url}</div>
            <div className="px-head__meta">{timeOf(f.timestamp)} &middot; status {f.status_code} &middot; {fmtBytes(f.response_size)} &middot; {f.duration_ms ?? '-'} ms</div>
          </div>
          <div style={{ padding: '12px 16px 0' }}>
            <div className="tabs" style={{ margin: 0 }}>
              <button className={'tab' + (tab === 'request' ? ' tab--active' : '')} onClick={() => setTab('request')}>Request</button>
              <button className={'tab' + (tab === 'response' ? ' tab--active' : '')} onClick={() => setTab('response')}>Response</button>
            </div>
          </div>
          {(() => {
            const H = (tab === 'request' ? f.request_headers : f.response_headers) || [];
            const B = (tab === 'request' ? f.request_body_preview : f.response_body_preview) || {};
            const text = B.encoding === 'text' ? B.text : '';
            return (
              <>
                <div className="msg-lbl">Headers</div>
                <div className="hdr-wrap"><table className="hdr-table"><tbody>{H.map((p, i) => <tr key={i}><td className="hdr-key">{p[0]}</td><td className="hdr-val">{p[1]}</td></tr>)}</tbody></table></div>
                <div className="msg-lbl">Body</div>
                {text ? <pre className="body-pre">{text}</pre> : <div className="body-meta" style={{ marginBottom: 16 }}>{B.present ? 'Binary or empty body.' : 'Empty body.'}</div>}
              </>
            );
          })()}
          <div className="sugg">
            <div className="sugg__head"><span className="sugg__title">Suggest attacks (send to scan)</span>
              <button className="btn btn--muted" onClick={suggest} disabled={sugg.loading}>{sugg.loading ? 'Analyzing...' : 'Suggest attacks'}</button>
            </div>
            {sugg.items == null ? <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-faint)' }}>Use the LLM to propose scans for this flow.</div> :
              sugg.items.length === 0 ? <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-faint)' }}>No attack suggestions for this flow.</div> :
                sugg.items.map((s, i) => (
                  <div key={i} className="sugg__item">
                    <span className="sugg__tool">{s.tool}</span>
                    <span className="sugg__why">{s.rationale || s.target}</span>
                    <button className="btn btn--solid btn--sm" onClick={() => runScan(s)} disabled={!engagementId}>Run</button>
                  </div>
                ))}
          </div>
        </div>
      )}
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
