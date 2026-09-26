import { useEffect, useRef, useState } from 'react';

/* Knowledge Map — a reusable "AI orb -> category cards" hero.
 *
 * Rebuilt for syphax from a public functional description (the original is a
 * paid component we do not have and did not copy): a dotted orb whose light
 * band sends a comet down the active wire to a column of category cards, each
 * with an icon tile, a count and a quality ring (high / medium / low). The
 * active card fans its breakdown out; a confidence ring under the orb tracks
 * the overall score. Every page feeds it its own categories, so one component
 * serves Home, Findings, Methodology, Surface and Reports.
 *
 * Hand-built in SVG + CSS (no animation library): the comet and orb band are
 * CSS keyframes, all disabled under prefers-reduced-motion. Colours come from
 * the brand tokens; the quality ring is a mono-orange -> grey intensity, always
 * paired with a label, so it never competes with the severity scale.
 *
 * Props:
 *   categories: [{ key, label, icon?, count, high?, med?, low? }]
 *   confidence: 0..100                      overall score in the orb ring
 *   activeKey / defaultActiveKey, onSelect  controlled or uncontrolled
 *   title, subtitle
 */
const QUALITY = [
  { k: 'high', color: '#ea580c', label: 'high' },
  { k: 'med', color: '#a3a3a3', label: 'medium' },
  { k: 'low', color: '#525252', label: 'low' },
];

function QualityRing({ high = 0, med = 0, low = 0, size = 46, thickness = 6 }) {
  const r = (size - thickness) / 2, cx = size / 2, C = 2 * Math.PI * r;
  const total = high + med + low;
  const segs = [high, med, low];
  let acc = 0;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true" className="km-qr">
      <circle cx={cx} cy={cx} r={r} fill="none" stroke="var(--border)" strokeWidth={thickness} />
      {total > 0 && segs.map((v, i) => {
        if (v <= 0) return null;
        const len = (v / total) * C;
        const el = (
          <circle key={i} cx={cx} cy={cx} r={r} fill="none" stroke={QUALITY[i].color} strokeWidth={thickness}
                  strokeDasharray={`${len} ${C - len}`} strokeDashoffset={-acc}
                  transform={`rotate(-90 ${cx} ${cx})`} strokeLinecap="butt" />
        );
        acc += len;
        return el;
      })}
      <text x={cx} y={cx} fill="var(--text-primary)" fontSize="13" fontFamily="var(--font-mono)"
            fontWeight="600" textAnchor="middle" dominantBaseline="central">{total}</text>
    </svg>
  );
}

export default function KnowledgeMap({
  categories = [], confidence = 0, activeKey, defaultActiveKey,
  onSelect, title = 'Knowledge map', subtitle,
}) {
  const cats = categories.slice(0, 5);
  const [internal, setInternal] = useState(defaultActiveKey || (cats[0] && cats[0].key) || null);
  const active = activeKey !== undefined ? activeKey : internal;
  const select = (k) => { if (onSelect) onSelect(k); if (activeKey === undefined) setInternal(k); };
  const activeIdx = Math.max(0, cats.findIndex((c) => c.key === active));
  const activeCat = cats[activeIdx];

  // Keyboard paging over the cards (radiogroup semantics).
  const listRef = useRef(null);
  function onKey(e) {
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(e.key)) return;
    e.preventDefault();
    let i = activeIdx;
    if (e.key === 'ArrowDown') i = Math.min(cats.length - 1, i + 1);
    else if (e.key === 'ArrowUp') i = Math.max(0, i - 1);
    else if (e.key === 'Home') i = 0;
    else if (e.key === 'End') i = cats.length - 1;
    if (cats[i]) select(cats[i].key);
  }
  useEffect(() => {
    const el = listRef.current?.querySelector('[data-active="true"]');
    el?.scrollIntoView?.({ block: 'nearest' });
  }, [active]);

  // Confidence ring geometry.
  const R = 34, C = 2 * Math.PI * R;
  const conf = Math.max(0, Math.min(100, Math.round(confidence)));
  const total = cats.reduce((n, c) => n + (c.count || 0), 0);

  return (
    <div className="km">
      <div className="km__head">
        <span className="km__title">{title}</span>
        {subtitle && <span className="km__sub">{subtitle}</span>}
      </div>

      <div className="km__body">
        {/* Orb + confidence ring */}
        <div className="km__orb" aria-hidden="true">
          <div className="km__band" />
          <div className="km__dots" />
          <svg className="km__conf" width="88" height="88" viewBox="0 0 88 88">
            <circle cx="44" cy="44" r={R} fill="none" stroke="var(--border)" strokeWidth="5" />
            <circle cx="44" cy="44" r={R} fill="none" stroke="var(--accent)" strokeWidth="5"
                    strokeLinecap="round" strokeDasharray={`${(conf / 100) * C} ${C}`}
                    transform="rotate(-90 44 44)" style={{ filter: 'drop-shadow(0 0 4px var(--accent))' }} />
            <text x="44" y="40" fill="var(--text-primary)" fontSize="19" fontFamily="var(--font-mono)"
                  fontWeight="600" textAnchor="middle" dominantBaseline="central">{conf}<tspan fontSize="11">%</tspan></text>
            <text x="44" y="56" fill="var(--text-faint)" fontSize="8" fontFamily="var(--font-mono)"
                  textAnchor="middle" dominantBaseline="central" style={{ letterSpacing: '.06em' }}>CONFIDENCE</text>
          </svg>
        </div>

        {/* Category cards */}
        <div className="km__cards" role="radiogroup" aria-label={title} ref={listRef} onKeyDown={onKey}>
          {cats.length === 0 && <div className="empty">No data to map yet.</div>}
          {cats.map((c) => {
            const on = c.key === active;
            return (
              <button key={c.key} type="button" role="radio" aria-checked={on}
                      data-active={on} tabIndex={on ? 0 : -1}
                      className={'km-card' + (on ? ' km-card--on' : '')}
                      onClick={() => select(c.key)}>
                <span className="km-card__wire" aria-hidden="true">{on && <span className="km-card__comet" />}</span>
                <span className="km-card__icon">{c.icon || c.label.slice(0, 2)}</span>
                <span className="km-card__body">
                  <span className="km-card__label">{c.label}</span>
                  <span className="km-card__count">{c.count || 0} <small>results</small></span>
                </span>
                <QualityRing high={c.high} med={c.med} low={c.low} />
              </button>
            );
          })}
        </div>
      </div>

      {/* Active card fan-out: its high/med/low breakdown */}
      {activeCat && (
        <div className="km__fan">
          <span className="km__fan-label">{activeCat.label} · {activeCat.count || 0} of {total}</span>
          <div className="km__fan-bars">
            {QUALITY.map((q) => {
              const v = activeCat[q.k] || 0;
              const pct = (activeCat.count || 0) > 0 ? Math.round((v / activeCat.count) * 100) : 0;
              return (
                <div key={q.k} className="km__fan-row">
                  <span className="km__fan-k" style={{ color: q.color }}>{q.label}</span>
                  <span className="km__fan-track"><span className="km__fan-fill" style={{ width: pct + '%', background: q.color }} /></span>
                  <span className="km__fan-n">{v}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
