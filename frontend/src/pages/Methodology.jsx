import { useEffect, useState } from 'react';
import { api } from '../lib/api.js';
import { useEngagements } from '../lib/useApi.js';
import { Notice } from '../components/ui.jsx';
import { COV_AXES, Donut, Legend, Radar } from '../components/Charts.jsx';
import KnowledgeMap from '../components/KnowledgeMap.jsx';

const FILTERS = ['all', 'done', 'running', 'queued', 'skipped', 'error'];
const STATUS_HEX = { done: '#22c55e', running: '#38bdf8', queued: '#737373', skipped: '#525252', error: '#ef4444' };

export default function Methodology() {
  const [loadError, setLoadError] = useState(null);
  // One shared picker: five pages each rebuilt this and each swallowed
  // its failure, so a dead backend looked exactly like an empty install.
  const { engagements, engId, setEngId, error: engError, reload: reloadEngagements } = useEngagements();
  const [cats, setCats] = useState([]);
  const [filter, setFilter] = useState('all');
  const [open, setOpen] = useState([]);
  const [standalone, setStandalone] = useState(false);

  // With an engagement selected we show its coverage. Without one (fresh
  // install, or before any engagement exists) fall back to the raw catalog so
  // the methodology is still browsable instead of showing an empty page.
  useEffect(() => {
    if (engId) {
      setStandalone(false);
      api.engagements.coverage(engId).then((r) => {
        const c = (r.categories || []).filter((g) => (g.items || []).length);
        setCats(c);
        setOpen(c.map((x) => x.cat));
      }).catch((e) => { setCats([]); setLoadError(e.message); });
      return;
    }
    setStandalone(true);
    api.methodology.catalog().then((r) => {
      const groups = {};
      for (const it of r.items || []) {
        const wstg = it.wstg_category || 'Other';
        (groups[wstg] = groups[wstg] || { cat: it.category || wstg, wstg, items: [] }).items.push({
          id: it.id,
          name: it.description || it.name,
          attack: it.attack_techniques || [],
          asset: '-',
          status: 'queued',
          hit: false,
        });
      }
      const c = Object.values(groups);
      setCats(c);
      setOpen(c.map((x) => x.cat));
    }).catch((e) => { setCats([]); setLoadError(e.message); });
  }, [engId]);

  const toggle = (cat) => setOpen((o) => o.includes(cat) ? o.filter((x) => x !== cat) : [...o, cat]);
  const allItems = cats.flatMap((c) => c.items);
  const done = allItems.filter((i) => i.status === 'done').length;
  const hits = allItems.filter((i) => i.hit).length;
  const cov = allItems.length ? Math.round(done / allItems.length * 100) : 0;

  // Chart data. The coverage radar comes from the engagement summary the list
  // already carries; the donut is the live status mix of the catalog items.
  const selected = engagements.find((e) => e.id === engId);
  const radarValues = selected?.radar;
  const statusSegments = FILTERS.filter((f) => f !== 'all')
    .map((s) => ({ label: s, value: allItems.filter((i) => i.status === s).length, color: STATUS_HEX[s] }))
    .filter((s) => s.value > 0);

  // Knowledge map over the WSTG categories: items covered = quality (done high,
  // running medium, queued/skipped low), confidence = overall coverage.
  const kmCats = cats
    .map((c) => {
      const items = c.items || [];
      return {
        key: c.cat, label: c.cat, icon: (c.cat[0] || '?').toUpperCase() + (c.cat.split(' ')[1]?.[0] || c.cat[1] || '').toUpperCase(),
        count: items.length,
        high: items.filter((i) => i.status === 'done').length,
        med: items.filter((i) => i.status === 'running').length,
        low: items.filter((i) => i.status !== 'done' && i.status !== 'running').length,
      };
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  return (
    <div className="page">
      <Notice kind="error" message={loadError} />
      <Notice kind="error" title="Could not load engagements"
              message={engError} onRetry={reloadEngagements} />
      <div className="lv-head">
        <div className="lv-title"><h1>Methodology coverage</h1><span className="lv-title__host">OWASP WSTG &middot; MITRE ATT&amp;CK</span></div>
        <div className="select-box"><select className="select" value={engId} onChange={(e) => setEngId(e.target.value)}>
          {engagements.length === 0 && <option value="">no engagements</option>}
          {engagements.map((e) => <option key={e.id} value={e.id}>{e.target_host || e.target_url}</option>)}
        </select></div>
      </div>

      <div className="metrics">
        <div className="metric"><div className="metric__l">Catalog items</div><div className="metric__v">{allItems.length}</div></div>
        <div className="metric metric--ok"><div className="metric__l">Completed</div><div className="metric__v">{done}</div><div className="metric__sub">{cov}% coverage</div></div>
        <div className="metric metric--alert"><div className="metric__l">Hits</div><div className="metric__v">{hits}</div></div>
        <div className="metric"><div className="metric__l">Queued</div><div className="metric__v">{allItems.filter((i) => i.status === 'queued').length}</div></div>
      </div>

      {(
        <div style={{ marginBottom: 16 }}>
          <KnowledgeMap categories={kmCats} confidence={cov}
                        title="Coverage map" subtitle={`${allItems.length} checks · ${cov}% completed · click a category to open it`}
                        idleNote="No coverage yet — run the engagement to populate the matrix."
                        metricLabel="coverage"
                        onSelect={(cat) => {
                          setOpen((o) => (o.includes(cat) ? o : [...o, cat]));
                          requestAnimationFrame(() => document.getElementById('cat-' + cat)?.scrollIntoView?.({ behavior: 'smooth', block: 'start' }));
                        }} />
        </div>
      )}

      {(radarValues || statusSegments.length > 0) && (
        <div className="viz-row" style={{ marginBottom: 16 }}>
          {radarValues && (
            <div className="viz">
              <div className="viz__h">Coverage by axis (WSTG)</div>
              <div className="viz__body" style={{ flexDirection: 'column' }}>
                <Radar values={radarValues} axes={COV_AXES} />
                <div className="radar-axes">
                  {COV_AXES.map((a, i) => <span key={a}>{a} <b>{radarValues[i]}%</b></span>)}
                </div>
              </div>
            </div>
          )}
          {statusSegments.length > 0 && (
            <div className="viz">
              <div className="viz__h">Test status mix</div>
              <div className="viz__body">
                <Donut segments={statusSegments} centerLabel="tests" />
                <Legend segments={statusSegments} />
              </div>
            </div>
          )}
        </div>
      )}

      <div className="meth-filters">
        <div className="meth-seg">
          {FILTERS.map((f) => <button key={f} className={filter === f ? 'on' : ''} onClick={() => setFilter(f)}>{f}</button>)}
        </div>
      </div>

      {standalone && cats.length > 0 && (
        <div className="card"><div className="card__body">
          <div className="empty">Reference catalog &mdash; every test the engine can run. Select an engagement to see which of these were actually executed against it.</div>
        </div></div>
      )}

      {cats.length === 0 && <div className="card"><div className="card__body"><div className="empty">No coverage yet. Run the engagement to populate the methodology matrix.</div></div></div>}

      {cats.map((c) => {
        const items = filter === 'all' ? c.items : c.items.filter((i) => i.status === filter);
        if (items.length === 0) return null;
        const d = c.items.filter((i) => i.status === 'done').length;
        const r = c.items.filter((i) => i.status === 'running').length;
        const q = c.items.length - d - r;
        const chits = c.items.filter((i) => i.hit).length;
        const isOpen = open.includes(c.cat);
        return (
          <div key={c.cat} id={"cat-" + c.cat} className="card cat">
            <div className="cat__head" role="button" tabIndex={0} aria-expanded={isOpen}
                 onClick={() => toggle(c.cat)}
                 onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(c.cat); } }}>
              <div><div className="cat__name">{c.cat}</div><div className="cat__wstg">{c.wstg}</div></div>
              <div className="cat__bar">
                <span className="cat__seg cat__seg--done" style={{ width: (d / c.items.length * 100) + '%' }}></span>
                <span className="cat__seg cat__seg--running" style={{ width: (r / c.items.length * 100) + '%' }}></span>
                <span className="cat__seg cat__seg--queued" style={{ width: (q / c.items.length * 100) + '%' }}></span>
              </div>
              <div className="cat__counts">{d}/{c.items.length}{chits > 0 ? <span className="hit"> &middot; {chits} hit</span> : null}</div>
              <span className={'cat__chev' + (isOpen ? ' open' : '')}></span>
            </div>
            {isOpen && (
              <div className="items">
                {items.map((it) => (
                  <div key={it.id} className="item">
                    <div><span className="item__name">{it.name}</span> <span className="item__id">{it.id}</span></div>
                    <div className="item__attack" title={(it.attack || []).join(', ')}>ATT&amp;CK {(it.attack || []).join(', ')}</div>
                    <div className="item__asset" title={it.asset}>{it.asset}</div>
                    <div className={'item__status st-' + it.status}>{it.hit ? <span className="st-hit">hit</span> : it.status}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
