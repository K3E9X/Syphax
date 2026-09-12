/* Presentational blocks lifted out of LiveView.
 *
 * LiveView had grown to 564 lines holding the console, the assets, the
 * coverage matrix, the jobs, the findings, the chains, the audit trail and the
 * token panel in one component. These three read only from their props - they
 * touch none of LiveView's state - so moving them costs nothing and takes a
 * third of the file with them.
 */
import { Async, Card } from '../ui.jsx';

export function ChainList({ chains }) {
  return (
    <div className="card">
      <div className="card__head"><span className="card__title">Kill-chains</span><span className="card__meta">{chains.length} multi-step paths</span></div>
      <div className="card__body">
        {chains.map((c) => (
          <div key={c.id} className="chain-card">
            <div className="chain-card__top">
              <span className={'sev sev--' + (c.severity || 'medium')}>{c.severity}</span>
              <span className="mono" style={{ fontSize: 11, color: 'var(--text-faint)' }}>source: {c.source}</span>
            </div>
            <div className="chain-card__title">{c.title}</div>
            {c.summary && <div className="chain-card__sum">{c.summary}</div>}
            <div className="chain-graph">
              {(c.steps || []).map((st, i) => (
                <span key={i}>{i > 0 ? <span className="chain-graph__arrow"></span> : null}<span className="chain-graph__node" title={st.reason}><span className="chain-graph__n">{i + 1}</span><span className="chain-graph__label">{st.action}</span></span></span>
              ))}
            </div>
            <ol className="chain-steps">
              {(c.steps || []).map((st, i) => (
                <li key={i} className="chain-step">
                  <div className="chain-step__rail"><span className="chain-step__dot">{i + 1}</span><span className="chain-step__line"></span></div>
                  <div><div className="chain-step__action">{st.action}</div><div className="chain-step__reason">{st.reason}</div></div>
                </li>
              ))}
            </ol>
          </div>
        ))}
        {chains.length === 0 && <div className="empty">No multi-step attack chains identified yet.</div>}
      </div>
    </div>
  );
}

export function CoverageMatrix({ coverage, covSummary }) {
  return (
    <div className="card">
      <div className="card__head"><span className="card__title">Methodology coverage</span><span className="card__meta">OWASP WSTG &middot; MITRE ATT&amp;CK</span></div>
      <div className="card__body">
        <div className="cov-summary">
          {Object.entries(covSummary).map(([k, v]) => <span key={k} className={k === 'done' ? 'hit' : ''}>{k}<b>{v}</b></span>)}
          {Object.keys(covSummary).length === 0 && <span style={{ color: 'var(--text-faint)' }}>Nothing run yet.</span>}
        </div>
      </div>
      <div className="tbl-scroll">
        <table className="tbl">
          <thead><tr><th>Catalog item</th><th>Asset</th><th>Status</th></tr></thead>
          <tbody>
            {coverage.map((c, i) => (
              <tr key={i}>
                <td className="mono">{c.catalog_item_id}</td>
                <td className="mono truncate" style={{ maxWidth: 360 }} title={c.asset_value}>{c.asset_value}</td>
                <td><span className={'st st--' + c.status}>{c.status}</span></td>
              </tr>
            ))}
            {coverage.length === 0 && <tr><td colSpan={3}><div className="empty">Coverage builds as the run progresses.</div></td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function AuditTrail({ audit, time }) {
  return (
    <Card title="Audit trail"
          meta={`${(audit.data?.items || []).length} recorded action(s)`}>
      <Async loading={audit.loading} error={audit.error} data={audit.data}
             onRetry={audit.reload} empty="No actions recorded yet."
             isEmpty={(d) => !d || !(d.items || []).length}>
        <div className="calls">
          {(audit.data?.items || []).map((a) => (
            <div key={a.id} className="calls__row" title={new Date((a.ts || 0) * 1000).toISOString()}>
              <span className="calls__role">{time(a.ts)}</span>
              <span className="calls__model">{a.action}</span>
              <span className="calls__n">
                {Object.keys(a.detail || {}).length
                  ? Object.entries(a.detail).slice(0, 3).map(([k, v]) =>
                      `${k}=${typeof v === 'object' ? JSON.stringify(v).slice(0, 40) : v}`).join(' ')
                  : ''}
              </span>
            </div>
          ))}
        </div>
      </Async>
    </Card>
  );
}
