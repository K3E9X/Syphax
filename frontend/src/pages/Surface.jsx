import { useEffect, useState } from 'react';
import { api } from '../lib/api.js';
import { useEngagements } from '../lib/useApi.js';
import { Notice } from '../components/ui.jsx';
import { Donut, Histogram, Legend } from '../components/Charts.jsx';
import KnowledgeMap from '../components/KnowledgeMap.jsx';

const METHOD_HEX = { GET: '#22c55e', POST: '#22d3ee', PUT: '#eab308', PATCH: '#a78bfa', DELETE: '#ef4444', HEAD: '#737373', OPTIONS: '#525252' };

export default function Surface() {
  const [loadError, setLoadError] = useState(null);
  // One shared picker: five pages each rebuilt this and each swallowed
  // its failure, so a dead backend looked exactly like an empty install.
  const { engagements, engId, setEngId, error: engError, reload: reloadEngagements } = useEngagements();
  const [hosts, setHosts] = useState([]);
  const [sel, setSel] = useState(null);
  const [q, setQ] = useState('');

  useEffect(() => {
    if (!engId) return;
    api.engagements.surface(engId).then((r) => {
      const hs = r.hosts || [];
      setHosts(hs);
      setSel(hs.length ? hs[0].host : null);
    }).catch((e) => { setHosts([]); setLoadError(e.message); });
  }, [engId]);

  const openPorts = (h) => (h.ports || []).filter((p) => p.state === 'open').length;
  const shown = hosts.filter((h) => !q || (h.host || '').toLowerCase().includes(q.toLowerCase()));
  const h = hosts.find((x) => x.host === sel);
  const totEndpoints = hosts.reduce((n, x) => n + (x.endpoints || []).length, 0);
  const totParams = hosts.reduce((n, x) => n + (x.endpoints || []).filter((e) => (e.params || []).length).length, 0);
  const totPorts = hosts.reduce((n, x) => n + openPorts(x), 0);
  const totTech = new Set(hosts.flatMap((x) => x.tech || [])).size;

  // Chart data. Where the surface concentrates (endpoints per host, top 8) and
  // the request-method mix across every discovered endpoint.
  const hostBars = hosts
    .map((x) => ({ label: x.host, value: (x.endpoints || []).length }))
    .filter((b) => b.value > 0)
    .sort((a, b) => b.value - a.value)
    .slice(0, 8)
    .map((b) => ({ ...b, color: '#c2410c' }));
  const methodCounts = {};
  for (const x of hosts) for (const e of x.endpoints || []) {
    const m = (e.m || 'GET').toUpperCase();
    methodCounts[m] = (methodCounts[m] || 0) + 1;
  }
  const methodSegments = Object.entries(methodCounts)
    .map(([m, n]) => ({ label: m, value: n, color: METHOD_HEX[m] || '#737373' }))
    .sort((a, b) => b.value - a.value);

  // Knowledge map over hosts: endpoints are the count, and "quality" is how
  // attackable they look - parameterised (high), a mutating method without
  // params (medium), the rest (low). Confidence = share of endpoints with
  // parameters across the whole surface.
  const MUT = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
  let totalEp = 0, totalParam = 0;
  const kmCats = hosts
    .map((x) => {
      const eps = x.endpoints || [];
      let high = 0, med = 0, low = 0;
      for (const e of eps) {
        if ((e.params || []).length) high += 1;
        else if (MUT.has((e.m || 'GET').toUpperCase())) med += 1;
        else low += 1;
      }
      totalEp += eps.length; totalParam += high;
      const host = x.host || '?';
      return { key: host, label: host, icon: (host[0] || '?').toUpperCase() + (host[1] || '').toUpperCase(),
               count: eps.length, high, med, low };
    })
    .filter((c) => c.count > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);
  const kmConfidence = totalEp ? Math.round((totalParam / totalEp) * 100) : 0;

  return (
    <div className="page">
      <Notice kind="error" message={loadError} />
      <Notice kind="error" title="Could not load engagements"
              message={engError} onRetry={reloadEngagements} />
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

      {kmCats.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <KnowledgeMap categories={kmCats} confidence={kmConfidence}
                        title="Surface map" subtitle={`${totalEp} endpoint(s) · ${kmConfidence}% parameterised`} />
        </div>
      )}

      {(hostBars.length > 0 || methodSegments.length > 0) && (
        <div className="viz-row" style={{ marginBottom: 16 }}>
          {hostBars.length > 0 && (
            <div className="viz">
              <div className="viz__h">Endpoints per host (top 8)</div>
              <div className="viz__body" style={{ width: '100%' }}><Histogram data={hostBars} /></div>
            </div>
          )}
          {methodSegments.length > 0 && (
            <div className="viz">
              <div className="viz__h">Request-method mix</div>
              <div className="viz__body">
                <Donut segments={methodSegments} centerLabel="endpoints" />
                <Legend segments={methodSegments} />
              </div>
            </div>
          )}
        </div>
      )}

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
