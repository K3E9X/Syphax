/* Small, dependency-free SVG charts, themed to the terminal palette.
 *
 * Deliberately hand-built rather than a chart library: the bundle stays small,
 * the look stays coherent with the rest of the hand-drawn viz (severity bars,
 * usage meters), and there is no runtime we do not control rendering into a
 * security tool. Grid and label colours come from CSS variables so they track
 * the theme; series colours are passed in (a severity red is red in any
 * theme, so those stay fixed).
 */

export const COV_AXES = ['Recon', 'Config', 'Injection', 'Auth', 'Session', 'API'];
export const SEV_HEX = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#06b6d4', info: '#737373' };

// ---- Radar ---------------------------------------------------------------- //
// values: number[] in 0..100, one per axis. axes: string[] labels.
export function Radar({ values = [], axes = COV_AXES, size = 176, accent = '#22d3ee' }) {
  const n = axes.length || 1;
  const c = size / 2, r = c - 28;
  const pt = (i, rad) => {
    const a = (-90 + (i * 360) / n) * Math.PI / 180;
    return [c + rad * Math.cos(a), c + rad * Math.sin(a)];
  };
  const ring = (rg) => axes.map((_, i) => pt(i, r * rg).join(',')).join(' ');
  const poly = axes.map((_, i) => pt(i, (r * (values[i] || 0)) / 100).join(',')).join(' ');
  return (
    <svg className="chart chart--radar" width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label="Testing coverage radar">
      {[0.33, 0.66, 1].map((rg, k) => (
        <polygon key={k} points={ring(rg)} fill="none" stroke="var(--border-strong)" strokeWidth="1" />
      ))}
      {axes.map((_, i) => { const [x, y] = pt(i, r); return <line key={i} x1={c} y1={c} x2={x} y2={y} stroke="var(--border-strong)" strokeWidth="1" />; })}
      <polygon points={poly} fill={accent} fillOpacity="0.15" stroke={accent} strokeWidth="1.5" />
      {axes.map((_, i) => { const [x, y] = pt(i, (r * (values[i] || 0)) / 100); return <circle key={i} cx={x} cy={y} r="2.5" fill={accent} />; })}
      {axes.map((lab, i) => { const [x, y] = pt(i, r + 15); return <text key={i} x={x} y={y} fill="var(--text-faint)" fontSize="9" fontFamily="var(--font-mono)" textAnchor="middle" dominantBaseline="middle">{lab}</text>; })}
    </svg>
  );
}

// ---- Donut (camembert) ---------------------------------------------------- //
// segments: [{ label, value, color }]. Renders a ring of arcs with the total in
// the middle. An all-zero input renders a single muted ring, never a crash.
export function Donut({ segments = [], size = 148, thickness = 22, center, centerLabel }) {
  const r = (size - thickness) / 2, cx = size / 2, C = 2 * Math.PI * r;
  const total = segments.reduce((a, s) => a + (s.value || 0), 0);
  let acc = 0;
  return (
    <svg className="chart chart--donut" width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label="Distribution">
      <circle cx={cx} cy={cx} r={r} fill="none" stroke="var(--border)" strokeWidth={thickness} />
      {total > 0 && segments.filter((s) => (s.value || 0) > 0).map((s, i) => {
        const len = ((s.value || 0) / total) * C;
        const el = (
          <circle key={i} cx={cx} cy={cx} r={r} fill="none" stroke={s.color} strokeWidth={thickness}
                  strokeDasharray={`${len} ${C - len}`} strokeDashoffset={-acc}
                  transform={`rotate(-90 ${cx} ${cx})`} />
        );
        acc += len;
        return el;
      })}
      <text x={cx} y={cx - 4} fill="var(--text-primary)" fontSize="22" fontFamily="var(--font-mono)" fontWeight="600" textAnchor="middle" dominantBaseline="middle">{center ?? total}</text>
      {centerLabel && <text x={cx} y={cx + 15} fill="var(--text-faint)" fontSize="9" fontFamily="var(--font-mono)" textAnchor="middle" dominantBaseline="middle" style={{ textTransform: 'uppercase', letterSpacing: '0.05em' }}>{centerLabel}</text>}
    </svg>
  );
}

// ---- Legend --------------------------------------------------------------- //
export function Legend({ segments = [], suffix = '' }) {
  return (
    <div className="chart-legend">
      {segments.map((s, i) => (
        <div key={i} className="chart-legend__row">
          <span className="chart-legend__dot" style={{ background: s.color }} />
          <span className="chart-legend__l">{s.label}</span>
          <span className="chart-legend__v">{s.value}{suffix}</span>
        </div>
      ))}
    </div>
  );
}

// ---- Histogram (vertical bars) -------------------------------------------- //
// data: [{ label, value, color }]. Baseline at the bottom, value on each bar.
export function Histogram({ data = [], height = 132, accent = '#22d3ee' }) {
  const max = Math.max(...data.map((d) => d.value || 0), 1);
  return (
    <div className="chart-hist" style={{ height }}>
      {data.map((d, i) => {
        const h = Math.round(((d.value || 0) / max) * 100);
        return (
          <div key={i} className="chart-hist__col" title={`${d.label}: ${d.value}`}>
            <div className="chart-hist__val">{d.value}</div>
            <div className="chart-hist__track">
              <div className="chart-hist__bar" style={{ height: h + '%', background: d.color || accent }} />
            </div>
            <div className="chart-hist__lab">{d.label}</div>
          </div>
        );
      })}
    </div>
  );
}
