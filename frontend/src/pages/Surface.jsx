import { useEffect, useState } from 'react';
import { api } from '../lib/api.js';

export default function Surface() {
  const [engagements, setEngagements] = useState([]);
  const [engId, setEngId] = useState('');
  const [hosts, setHosts] = useState([]);
  const [sel, setSel] = useState(null);
  const [q, setQ] = useState('');

  useEffect(() => {
    api.engagements.list().then((r) => {
      const items = r.items || [];
      setEngagements(items);
      if (items.length) setEngId(items[0].id);
    }).catch(() => {});
  }, []);
  useEffect(() => {
    if (!engId) return;
    api.engagements.surface(engId).then((r) => {
      const hs = r.hosts || [];
      setHosts(hs);
      setSel(hs.length ? hs[0].host : null);
    }).catch(() => setHosts([]));
  }, [engId]);

  const openPorts = (h) => (h.ports || []).filter((p) => p.state === 'open').length;
  const shown = hosts.filter((h) => !q || (h.host || '').toLowerCase().includes(q.toLowerCase()));
  const h = hosts.find((x) => x.host === sel);
  const totEndpoints = hosts.reduce((n, x) => n + (x.endpoints || []).length, 0);
  const totParams = hosts.reduce((n, x) => n + (x.endpoints || []).filter((e) => (e.params || []).length).length, 0);
  const totPorts = hosts.reduce((n, x) => n + openPorts(x), 0);
  const totTech = new Set(hosts.flatMap((x) => x.tech || [])).size;

  return (
    <div className="page">
      <div className="lv-head">
        <div className="lv-title"><h1>Attack surface</h1></div>
        <div className="select-box"><select className="select" value={engId} onChange={(e) => setEngId(e.target.value)}>
          {engagements.length === 0 && <option value="">no engagements</option>}
          {engagements.map((e) => <option key={e.id} value={e.id}>{e.target_host || e.target_url}</option>)}
        </select></div>
      </div>

      <div className="metrics">
        <div className="metric"><div className="metric__l">Hosts</div><div className="metric__v">{hosts.length}</div></div>
        <div className="metric"><div className="metric__l">Endpoints</div><div className="metric__v">{totEndpoints}</div><div className="metric__sub">{totParams} with parameters</div></div>
        <div className="metric metric--alert"><div className="metric__l">Open ports</div><div className="metric__v">{totPorts}</div></div>
        <div className="metric"><div className="metric__l">Technologies</div><div className="metric__v">{totTech}</div></div>
      </div>

      <div className="surf-layout">
        <div className="card">
          <div className="card__head"><span className="card__title">Discovered hosts</span><span className="card__meta">click a host for ports &amp; endpoints</span></div>
          <div className="card__body" style={{ paddingBottom: 0, paddingTop: 14 }}>
            <input className="surf-search" placeholder="filter hosts..." value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <div>
            {shown.map((x) => (
              <div key={x.host} className={'host-row' + (x.host === sel ? ' sel' : '')} onClick={() => setSel(x.host)}>
                <div><div className="host-row__name">{x.host}</div><div className="host-row__sub">{(x.tech || []).slice(0, 2).join(' · ') || 'unknown'} · via {x.source || 'discovery'}</div></div>
                <div className={'host-row__n' + (openPorts(x) > 1 ? ' hit' : '')}>{openPorts(x)}<small> ports</small></div>
                <div className="host-row__n">{(x.endpoints || []).length}<small> ep</small></div>
              </div>
            ))}
            {shown.length === 0 && <div className="empty">No surface mapped yet. Run the engagement to discover hosts, ports and endpoints.</div>}
          </div>
        </div>

        {h && (
          <div className="card detail">
            <div className="card__body">
              <h2 className="detail__h">{h.host}</h2>
              <div className="detail__hsub">{h.https ? 'https' : 'http'} · discovered via {h.source || 'discovery'}</div>

              <div className="block-t">Open ports</div>
              {(h.ports || []).length === 0 ? <div className="empty" style={{ padding: '12px 0' }}>No port scan data.</div> : (
                <table className="ports">
                  <thead><tr><th>Port</th><th>Service</th><th>Version</th><th>State</th></tr></thead>
                  <tbody>
                    {h.ports.map((p, i) => (
                      <tr key={i}>
                        <td className="ports__port">{p.port}/{p.proto}</td>
                        <td>{p.service || '-'}</td>
                        <td style={{ color: 'var(--text-secondary)' }}>{p.version || '-'}</td>
                        <td><span className={'ports__state' + (p.state === 'filtered' ? ' filtered' : '')}>{p.state}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}

              <div className="block-t">Technology</div>
              <div className="tech-chips">{(h.tech || []).length ? h.tech.map((t) => <span key={t} className="tech-chip">{t}</span>) : <span className="empty">unknown</span>}</div>

              <div className="block-t">Endpoints ({(h.endpoints || []).length})</div>
              <div>
                {(h.endpoints || []).map((e, i) => (
                  <div key={i} className="ep">
                    <span className="ep__m">{e.m}</span>
                    <span className="ep__path">{e.path} {(e.params || []).length ? <span className="ep__param">[{e.params.join(', ')}]</span> : null}</span>
                    <span className="ep__status">{e.status ?? '-'}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
