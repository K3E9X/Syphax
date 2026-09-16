/* Token consumption, broken down every way the backend records it.
 *
 * llm_usage has always stored the role, the timestamp and the prompt/
 * completion split. The UI showed one total and a per-model bar, so the
 * actionable question - which part of the system is spending this - had no
 * answer. The planner is re-invoked on every loop iteration, which is the
 * usual reason a run costs more than expected; now that is visible.
 */
import { Async, Card, Empty, Stat, UsageRow, fmtTokens, fmtUsd } from './ui.jsx';

const ROLE_LABEL = { planner: 'Planner', executor: 'Executor', validator: 'Validator' };

function roleLabel(role) {
  return ROLE_LABEL[role] || role || '(unknown)';
}

function relTime(ts) {
  const secs = Math.max(0, Date.now() / 1000 - (Number(ts) || 0));
  if (secs < 90) return `${Math.round(secs)}s ago`;
  if (secs < 5400) return `${Math.round(secs / 60)}m ago`;
  return `${Math.round(secs / 3600)}h ago`;
}

/** Tokens over time. One bar per bucket, scaled to the busiest one. */
export function Sparkline({ buckets = [], label }) {
  if (!buckets.length) return <Empty>No calls recorded yet.</Empty>;
  const peak = Math.max(...buckets, 1);
  return (
    <div>
      <div className="spark" role="img"
           aria-label={`${label || 'Activity'}: ${buckets.length} time buckets, peak ${fmtTokens(peak)}`}>
        {buckets.map((v, i) => (
          <span key={i}
                className={'spark__b' + (v ? '' : ' spark__b--empty')}
                style={{ height: Math.max(2, (v / peak) * 100) + '%' }}
                title={`${fmtTokens(v)} tokens`} />
        ))}
      </div>
      <div className="spark__axis"><span>start of run</span><span>peak {fmtTokens(peak)}</span><span>now</span></div>
    </div>
  );
}

/** The prompt/completion ratio. A run at 95% prompt is wasted context. */
export function PromptSplit({ prompt = 0, completion = 0 }) {
  const total = prompt + completion;
  if (!total) return null;
  const pPct = Math.round((prompt / total) * 100);
  return (
    <div>
      <div className="tok__split" role="img"
           aria-label={`${pPct}% prompt, ${100 - pPct}% completion`}>
        <span className="tok__split-seg tok__split-seg--prompt" style={{ width: pPct + '%' }} />
        <span className="tok__split-seg tok__split-seg--completion" style={{ width: (100 - pPct) + '%' }} />
      </div>
      <div className="tok__legend">
        <span><i className="tok__dot tok__dot--prompt" />prompt <b>{fmtTokens(prompt)}</b> ({pPct}%)</span>
        <span><i className="tok__dot tok__dot--completion" />completion <b>{fmtTokens(completion)}</b></span>
      </div>
    </div>
  );
}

/**
 * `usage` is the payload of GET /api/engagements/{id}/usage.
 * `compact` drops the timeline and the call list, for the narrow Home column.
 */
export default function TokenPanel({ usage, loading, error, onRetry, compact = false }) {
  const u = usage || {};
  const budget = u.budget || {};
  const roles = u.by_role || [];
  const top = u.top_calls || [];
  const timeline = u.timeline || {};

  return (
    <Card title="Token consumption"
          meta={u.cost_usd != null ? fmtUsd(u.cost_usd, 4) : null}
          metaClass={budget.over ? 'kv-no' : ''}>
      <Async loading={loading} error={error} data={usage} onRetry={onRetry}
             empty="No LLM calls on this engagement yet."
             isEmpty={(d) => !d || !d.calls}>
        <div className="tok">
          {budget.over && (
            <div className="notice notice--warn" role="status">
              <div className="notice__body">
                <strong className="notice__t">Engagement budget reached</strong>
                <span className="notice__m">
                  {fmtUsd(budget.spend_usd)} spent against a {fmtUsd(budget.limit_usd)} cap.
                  The run stops here; raise or clear the cap in Settings.
                </span>
              </div>
            </div>
          )}

          <div className="tok__grid">
            <Stat label="Tokens" value={fmtTokens(u.total_tokens)} />
            <Stat label="Calls" value={u.calls || 0} />
            <Stat label="Cost" value={fmtUsd(u.cost_usd, 4)} />
            <Stat label="Burn rate" value={fmtTokens(u.tokens_per_min) + '/min'}
                  title="Tokens per minute over the window this engagement has been running" />
            {u.confirmed_findings > 0 && (
              <Stat label="Per finding" value={fmtUsd(u.cost_per_finding_usd, 3)} kind="alert"
                    title={`${fmtUsd(u.cost_usd, 4)} spent for ${u.confirmed_findings} confirmed finding(s)`} />
            )}
            {budget.limit_usd > 0 && (
              <Stat label="Of budget" value={budget.pct + '%'}
                    title={`Cap: ${fmtUsd(budget.limit_usd)} for this engagement`} />
            )}
          </div>

          <PromptSplit prompt={u.prompt_tokens} completion={u.completion_tokens} />

          {roles.length > 0 && (
            <div>
              <div className="tok__legend" style={{ marginBottom: 4 }}>
                <span>By role — which part of the system is spending</span>
              </div>
              <div className="usage">
                {roles.map((r) => (
                  <UsageRow key={r.key} label={roleLabel(r.key)} pct={r.pct}
                            value={fmtTokens(r.tokens)}
                            title={`${r.calls} call(s) · ${fmtUsd(r.cost_usd, 4)} · ${r.pct}% of all tokens`} />
                ))}
              </div>
            </div>
          )}

          {!compact && timeline.buckets && (
            <div>
              <div className="tok__legend" style={{ marginBottom: 4 }}>
                <span>Tokens over the run</span>
              </div>
              <Sparkline buckets={timeline.buckets} label="Tokens over the run" />
            </div>
          )}

          {!compact && top.length > 0 && (
            <div>
              <div className="tok__legend" style={{ marginBottom: 4 }}>
                <span>Most expensive calls — where a single prompt ate the budget</span>
              </div>
              <div className="calls">
                {top.map((c, i) => (
                  <div key={i} className="calls__row" title={relTime(c.ts)}>
                    <span className="calls__role">{roleLabel(c.role)}</span>
                    <span className="calls__model">{c.model}</span>
                    <span className="calls__n">
                      {fmtTokens(c.tokens)}
                      {c.cost_usd > 0 && <> · {fmtUsd(c.cost_usd, 4)}</>}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </Async>
    </Card>
  );
}
