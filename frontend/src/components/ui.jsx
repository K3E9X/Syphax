/* Shared UI primitives.
 *
 * Three components served eleven pages, so `.card`, `.metric`, `.stat`,
 * `.empty`, `.kv` and the severity/status chips were copy-pasted JSX. A
 * styling change meant eleven edits, and the error affordance drifted into
 * four different shapes (`form-error`, `scan-error`, `budget-alert`, inline
 * styles).
 *
 * These wrap the EXISTING class names rather than introducing new ones, so
 * the rendered output is unchanged - this is consolidation, not a restyle.
 */
export function Card({ title, meta, metaClass = '', children, className = '', ...rest }) {
  return (
    <div className={('card ' + className).trim()} {...rest}>
      {(title || meta) && (
        <div className="card__head">
          {title && <span className="card__title">{title}</span>}
          {meta != null && <span className={('card__meta ' + metaClass).trim()}>{meta}</span>}
        </div>
      )}
      <div className="card__body">{children}</div>
    </div>
  );
}

export function Metric({ label, value, sub, kind = '' }) {
  return (
    <div className={('metric ' + (kind ? 'metric--' + kind : '')).trim()}>
      <div className="metric__l">{label}</div>
      <div className="metric__v">{value}</div>
      {sub != null && <div className="metric__sub">{sub}</div>}
    </div>
  );
}

export function Stat({ label, value, kind = '', title }) {
  return (
    <div className={('stat ' + (kind ? 'stat--' + kind : '')).trim()} title={title}>
      <div className="stat__l">{label}</div>
      <div className="stat__v">{value}</div>
    </div>
  );
}

export function Empty({ children = 'Nothing here yet.' }) {
  return <div className="empty">{children}</div>;
}

export function KV({ children }) {
  return <dl className="kv">{children}</dl>;
}

export function SeverityChip({ severity }) {
  const s = (severity || 'info').toLowerCase();
  return <span className={'sev sev--' + s}>{s}</span>;
}

export function StatusChip({ status, confidence }) {
  return (
    <span className={'vstatus vstatus--' + status}>
      {status}
      {confidence != null && <> &middot; {Math.round((confidence || 0) * 100)}%</>}
    </span>
  );
}

/**
 * The single error/warning affordance.
 *
 * `kind` is 'error' | 'warn' | 'info'. Rendering nothing for an empty message
 * lets a caller write `<Notice message={error} />` unconditionally.
 */
export function Notice({ kind = 'error', title, message, children, onRetry }) {
  if (!message && !children) return null;
  return (
    <div className={'notice notice--' + kind} role={kind === 'error' ? 'alert' : 'status'}>
      <div className="notice__body">
        {title && <strong className="notice__t">{title}</strong>}
        {message && <span className="notice__m">{message}</span>}
        {children}
      </div>
      {onRetry && (
        <button type="button" className="btn btn--muted btn--sm" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

/**
 * What a panel shows before its data arrives, when it failed, or when it is
 * genuinely empty - so "loading", "broken" and "nothing found" stay three
 * distinguishable states instead of one blank area.
 */
export function Async({ loading, error, data, onRetry, empty, children,
                        isEmpty = (d) => d == null || (Array.isArray(d) && d.length === 0) }) {
  if (error) return <Notice kind="error" message={error} onRetry={onRetry} />;
  if (loading && data == null) return <div className="empty empty--loading">Loading…</div>;
  if (isEmpty(data)) return <Empty>{empty || 'Nothing here yet.'}</Empty>;
  return children;
}

/** Proportional bar, as used by the model-usage rows. */
export function Bar({ pct, kind = '' }) {
  const width = Math.max(0, Math.min(100, Number(pct) || 0));
  return (
    <span className="usage__bar">
      <span className={('usage__fill ' + (kind ? 'usage__fill--' + kind : '')).trim()}
            style={{ width: width + '%' }} />
    </span>
  );
}

export function UsageRow({ label, pct, value, kind = '', title }) {
  return (
    <div className="usage__row" title={title}>
      <span className="usage__l">{label}</span>
      <Bar pct={pct} kind={kind} />
      <span className="usage__n">{value}</span>
    </div>
  );
}

/* Formatters shared by every panel that prints tokens or money, so 1.2M
   tokens reads the same everywhere. */
export function fmtTokens(n) {
  const v = Number(n) || 0;
  if (v >= 1e6) return (v / 1e6).toFixed(2) + 'M';
  if (v >= 1000) return (v / 1000).toFixed(1) + 'k';
  return String(v);
}

export function fmtUsd(n, digits = 2) {
  return '$' + (Number(n) || 0).toFixed(digits);
}
