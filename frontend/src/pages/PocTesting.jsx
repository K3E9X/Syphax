import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api.js';
import { Notice, activateOnKey } from '../components/ui.jsx';
import { useEngagements } from '../lib/useApi.js';

/**
 * What was tried against this target, and did it work.
 *
 * The exploitation story used to be spread across three screens: the live
 * console said a PoC ran, the Sandbox page held the code, the finding carried
 * the output. Nothing answered the one question an operator actually asks.
 *
 * One row per proof-of-concept - published, written by the model, or staged by
 * hand - with its two readings, the command it was given, and what it printed.
 */

const ORIGIN_LABEL = {
  public: 'published', authored: 'written by the model',
  chain: 'kill-chain', manual: 'staged by hand',
};

function Verdict({ item }) {
  if (item.proved) return <span className="sev sev--critical">proved</span>;
  if (item.ran) return <span className="sev sev--medium">ran · exit {item.exit_code}</span>;
  if (item.vetting_allowed === false) return <span className="sev sev--low">refused</span>;
  return <span className="sev sev--info">not run</span>;
}

// Why this one has not run.
//
// This used to say, for every unexecuted PoC, "a PoC whose static inspection
// says it attacks YOU is never run automatically". That is one reason out of
// several, and it was shown next to PoCs whose inspection said "review" and
// whose target vetting said "allowed" — i.e. it asserted the opposite of what
// the two readings right above it reported. Say the reason that applies.
export function notRunBecause(poc) {
  if (!poc) return '';
  if (poc.inspection_verdict === 'hostile') {
    return 'Not run: static inspection found a critical signal — credential '
      + 'theft, a reverse shell, persistence or something destructive. That is '
      + 'a risk to YOU, not to the target, so it waits for a human. Read it on '
      + 'the Sandbox page and decide there.';
  }
  if (poc.vetting_allowed === false) {
    return 'Not run: the target-safety vet refused it'
      + (poc.vetting_summary ? ` — ${poc.vetting_summary}` : '')
      + '. Approving does not override that; the engagement would have to '
      + 'authorize the capability it needs.';
  }
  return 'Not run yet. Both readings passed'
    + (poc.inspection_verdict ? ` (operator safety: ${poc.inspection_verdict}, ` : ' (')
    + 'target vetting: allowed), so nothing is blocking it — it was staged and '
    + 'the run ended before it was executed, or auto-run is off in Settings. '
    + 'Approve and run it from the Sandbox page.';
}

export default function PocTesting() {
  const { engagements, engId, setEngId, error: engError } = useEngagements();
  const [data, setData] = useState({ counts: {}, items: [] });
  const [sel, setSel] = useState(null);
  const [loadError, setLoadError] = useState(null);

  const load = useCallback(async () => {
    try {
      setData(await api.poc.overview(engId === '__all__' ? '' : engId));
      setLoadError(null);
    } catch (e) { setLoadError(e.message); }
  }, [engId]);
  useEffect(() => { load(); }, [load]);

  const items = data.items || [];
  const c = data.counts || {};
  const open = items.find((x) => x.id === sel) || null;

  const kpi = (label, value, cls = '') => (
    <div className={'fkpi ' + cls}>
      <span className="fkpi__v">{value ?? 0}</span>
      <span className="fkpi__l">{label}</span>
    </div>
  );

  return (
    <div className="page">
      <h1 className="sr-only">PoC testing</h1>
      <Notice kind="error" message={loadError || engError} />

      <div className="fkpis">
        {kpi('Staged', c.total)}
        {kpi('Executed', c.executed)}
        {kpi('Proved', c.proved, 'fkpi--critical')}
        {kpi('Waiting for you', c.waiting)}
        {kpi('Refused', c.refused)}
      </div>

      <div className="filters">
        <div className="select-box">
          <select className="select" value={engId} onChange={(e) => setEngId(e.target.value)}>
            <option value="__all__">All engagements</option>
            {engagements.map((e) => (
              <option key={e.id} value={e.id}>{e.target_host || e.target_url}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="layout">
        <div className="card">
          <div className="card__head">
            <span className="card__title">Proofs of concept <span style={{ color: 'var(--text-faint)' }}>({items.length})</span></span>
            <span className="card__meta">published · written by the model · staged by hand</span>
          </div>
          <div className="tbl-scroll">
            <table className="tbl">
              <thead>
                <tr><th>Verdict</th><th>Origin</th><th>Source</th><th>Readings</th><th>Engagement</th></tr>
              </thead>
              <tbody>
                {items.map((p) => (
                  <tr key={p.id} className={'clickable' + (p.id === sel ? ' selected' : '')}
                      tabIndex={0} onClick={() => setSel(p.id)}
                      onKeyDown={activateOnKey(() => setSel(p.id))}>
                    <td><Verdict item={p} /></td>
                    <td>{ORIGIN_LABEL[p.origin] || p.origin}</td>
                    <td className="mono truncate" style={{ maxWidth: 220 }} title={`${p.repo}/${p.path}`}>
                      {p.repo}{p.path ? ` / ${p.path}` : ''}
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-faint)' }}>
                      {p.vetting_allowed === false ? 'target: refused' : 'target: ok'}
                      {' · '}{p.inspection_verdict || '—'}
                    </td>
                    <td className="mono" style={{ fontSize: 11, color: 'var(--text-faint)' }}>{p.engagement}</td>
                  </tr>
                ))}
                {items.length === 0 && (
                  <tr><td colSpan={5}><div className="empty-detail">
                    No proof of concept yet. They appear here as soon as a run finds a
                    CVE with a published exploit, or asks the model to write one.
                  </div></td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="card detail">
          {!open ? (
            <div className="empty-detail">Select a proof of concept.</div>
          ) : (
            <div className="card__body">
              <h2 className="detail__title">{open.repo}{open.path ? ` / ${open.path}` : ''}</h2>
              <div className="detail__row">
                <Verdict item={open} />
                <span className="status-pill">{open.status}</span>
                {open.decided_by && <span className="card__meta">by {open.decided_by}</span>}
              </div>

              <dl className="detail__meta">
                <dt>Origin</dt><dd>{ORIGIN_LABEL[open.origin] || open.origin}</dd>
                <dt>Language</dt><dd>{open.language || '—'}</dd>
                <dt>Target vetting</dt><dd>{open.vetting_allowed === false ? `refused — ${open.vetting_summary || ''}` : 'allowed'}</dd>
                <dt>Operator safety</dt><dd>{open.inspection_verdict || '—'}</dd>
                {open.rehearsed != null && (
                  <>
                    <dt>Rehearsal</dt>
                    <dd>{open.rehearsed} round(s) — {open.demonstrated ? 'demonstrated it' : 'did not demonstrate it'}</dd>
                  </>
                )}
              </dl>

              {open.argv?.length > 0 && (
                <>
                  <div className="io-label">Command it was given</div>
                  <pre className="detail__pre poc">{open.argv.join(' ')}</pre>
                </>
              )}

              {open.ran ? (
                <>
                  <div className="io-label">What it printed — exit {open.exit_code}</div>
                  <pre className="detail__pre poc">{open.stdout || '(no stdout)'}</pre>
                  {open.stderr && <pre className="detail__pre poc">{open.stderr}</pre>}
                </>
              ) : (
                <p className="poc-note">{notRunBecause(open)}</p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
