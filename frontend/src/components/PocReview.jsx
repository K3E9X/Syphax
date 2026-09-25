import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api.js';

/**
 * Review third-party PoCs fetched from GitHub before any of them runs.
 *
 * The screen is built around one assumption: the operator has to actually read
 * the code. So the code is the largest element, the inspection sits above it
 * pointing at line numbers, and Approve only exists once a file is open - it is
 * not reachable from the list. Approving straight off a verdict badge would
 * make the whole staging pipeline decorative.
 *
 * Run is disabled whenever the runner reports its egress was never pinned. The
 * backend refuses that case too; showing it here means the operator learns why
 * the button is dead instead of getting a 503 after clicking.
 */

const SEV_ORDER = { critical: 0, high: 1, medium: 2, info: 3 };

function Verdict({ verdict }) {
  const label = { hostile: 'hostile', suspicious: 'suspicious', review: 'needs review' }[verdict]
    || verdict || 'unknown';
  return <span className={'poc-verdict poc-verdict--' + (verdict || 'review')}>{label}</span>;
}

/**
 * Where the code came from. A reviewer treats a script a model wrote in the
 * last minute differently from one a researcher published after studying the
 * bug, and nothing else on this screen tells them which is which.
 */
function Origin({ origin }) {
  if (origin === 'chain') {
    return <span className="poc-origin poc-origin--chain" title="Multi-step exploit chaining several findings">chain</span>;
  }
  if (origin === 'authored') {
    return <span className="poc-origin poc-origin--authored" title="Written by the model for this finding">authored</span>;
  }
  if (origin === 'public') {
    return <span className="poc-origin poc-origin--public" title="Published third-party exploit">public</span>;
  }
  return <span className="poc-origin" title="Staged by hand">manual</span>;
}

/**
 * Whether it may run at all.
 *
 * Separate from the inspection verdict, because they answer different
 * questions: the inspection asks whether the code attacks YOU, this asks
 * whether what it does to the target is something an engagement can defend.
 * A refusal here is not overridable by approving — /api/poc/{id}/run re-checks
 * it — so it belongs in the list, not buried in the detail panel.
 */
function Fitness({ vetting }) {
  if (!vetting) return <span className="poc-fit">—</span>;
  if (vetting.allowed) {
    return vetting.requires?.length
      ? <span className="poc-fit poc-fit--ok" title={vetting.summary}>ok · authorized</span>
      : <span className="poc-fit poc-fit--ok">ok</span>;
  }
  // Naming the capability turns "refused" into something the operator can act
  // on: it is a checkbox on the engagement, not a wall.
  const missing = (vetting.missing || []).join(', ');
  return (
    <span className="poc-fit poc-fit--no" title={vetting.summary}>
      {missing ? `needs ${missing}` : 'out of scope'}
    </span>
  );
}

export default function PocReview({ engagementId }) {
  const [items, setItems] = useState([]);
  const [open, setOpen] = useState(null);       // full staged PoC incl. code
  const [runner, setRunner] = useState(null);
  const [repoUrl, setRepoUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  const [listError, setListError] = useState(null);
  const load = useCallback(async () => {
    if (!engagementId) return;
    try {
      setItems((await api.poc.list(engagementId)).items || []);
      setListError(null);
    } catch (e) {
      // This was an empty catch. A failed list rendered as "no staged PoCs",
      // which is the same thing the panel shows when there genuinely are none.
      setListError(e.message);
    }
  }, [engagementId]);

  useEffect(() => { load(); setOpen(null); setResult(null); }, [load]);
  // Swallowing this left the panel saying "runner unavailable" with no way to
  // tell a container that was never started from one that crashed or is
  // unreachable - the operator had two words and nothing to act on.
  const [runnerError, setRunnerError] = useState(null);
  const loadRunner = useCallback(() => {
    setRunnerError(null);
    return api.poc.runnerHealth()
      .then((r) => { setRunner(r); return r; })
      .catch((e) => { setRunner(null); setRunnerError(e.message); });
  }, []);
  useEffect(() => { loadRunner(); }, [loadRunner]);

  async function stage() {
    setBusy(true); setError(null);
    try {
      await api.poc.stage({ engagement_id: engagementId, repo_url: repoUrl });
      setRepoUrl('');
      await load();
    } catch (e) { setError(e.message); } finally { setBusy(false); }
  }

  async function openPoc(id) {
    setError(null); setResult(null);
    try { setOpen(await api.poc.get(id)); } catch (e) { setError(e.message); }
  }

  // Spelled out rather than dispatched through api.poc[action]: dynamic
  // lookups hide these calls from any static sweep of what the UI actually uses.
  const approve = () => decide(() => api.poc.approve(open.id));
  const reject = () => decide(() => api.poc.reject(open.id));

  async function decide(call) {
    setBusy(true); setError(null);
    try {
      await call();
      await load();
      setOpen(await api.poc.get(open.id));
    } catch (e) { setError(e.message); } finally { setBusy(false); }
  }

  async function runPoc() {
    setBusy(true); setError(null); setResult(null);
    try {
      const r = await api.poc.run(open.id);
      setResult(r.result);
      await load();
      setOpen(await api.poc.get(open.id));
    } catch (e) { setError(e.message); } finally { setBusy(false); }
  }

  const signals = (open?.inspection?.signals || [])
    .slice().sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
  const egressLocked = runner?.egress_locked;

  return (
    <>
      <div className="card">
        <div className="card__head">
          <span className="card__title">Public PoCs</span>
          <span className="card__meta">
            {runner?.status === 'ok'
              ? (egressLocked ? 'runner ready · egress pinned' : 'runner up · EGRESS NOT PINNED')
              : 'runner unavailable'}
          </span>
        </div>
        <div className="card__body">
          {runnerError && (
            <div className="notice notice--error" role="alert">
              <div className="notice__body">
                <strong className="notice__t">Sandbox runner unreachable</strong>
                <span className="notice__m">{runnerError}</span>
                <span className="notice__m">
                  Check the container is up: <code>docker compose ps sandbox-runner</code>
                </span>
              </div>
              <button type="button" className="btn btn--muted btn--sm" onClick={loadRunner}>Retry</button>
            </div>
          )}
          {listError && (
            <div className="notice notice--error" role="alert">
              <div className="notice__body">
                <strong className="notice__t">Could not list staged PoCs</strong>
                <span className="notice__m">{listError}</span>
              </div>
              <button type="button" className="btn btn--muted btn--sm" onClick={load}>Retry</button>
            </div>
          )}
          {runner?.status === 'ok' && !egressLocked && (
            <p className="ping-result ping-result--err">
              The sandbox started without an egress policy. Running untrusted code now
              would give it unrestricted outbound access — the backend refuses to send it work.
            </p>
          )}

          <p className="intro">
            Fetch a PoC published for a CVE, read it, then decide. Nothing runs until you
            approve it, and what you approve runs in the isolated container — not here.
          </p>

          <div className="key-row">
            <input className="input" placeholder="https://github.com/owner/CVE-2024-1234"
                   value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)} />
            <button className="btn btn--solid" onClick={stage}
                    disabled={!repoUrl || !engagementId || busy}>Stage</button>
          </div>
          {error && <p className="ping-result ping-result--err">{error}</p>}

          {items.length === 0 && <div className="empty">Nothing staged for this engagement.</div>}
          {items.length > 0 && (
            <table className="tbl poc-tbl">
              <thead>
                <tr><th>Origin</th><th>Source</th><th>File</th><th>Fit to run</th><th>Inspection</th><th>Status</th></tr>
              </thead>
              <tbody>
                {items.map((p) => (
                  <tr key={p.id} className={open?.id === p.id ? 'on' : ''}
                      onClick={() => openPoc(p.id)}>
                    <td><Origin origin={p.inspection?.origin} /></td>
                    <td className="mono truncate" style={{ maxWidth: 200 }} title={p.repo}>{p.repo}</td>
                    <td className="mono">{p.path}</td>
                    <td><Fitness vetting={p.inspection?.vetting} /></td>
                    <td><Verdict verdict={p.inspection?.verdict} /></td>
                    <td><span className={'st poc-st--' + p.status}>{p.status}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {open && (
        <div className="card">
          <div className="card__head">
            <span className="card__title">{open.repo} / {open.path}</span>
            <Verdict verdict={open.inspection?.verdict} />
          </div>
          <div className="card__body">
            <p className="poc-summary">{open.inspection?.summary}</p>

            {open.inspection?.origin === 'authored' && !open.inspection?.refine && (
              <p className="poc-note">
                Written by the model for this finding
                {open.inspection?.attempts > 1
                  ? ` (rewritten after ${open.inspection.attempts - 1} refusal)` : ''}.
                It has never run. Read it as you would a stranger&apos;s.
              </p>
            )}

            {open.inspection?.chain && (
              <div className="poc-chain">
                <div className="poc-chain__h">
                  Chained exploit — {open.inspection.chain.title || 'kill-chain'}
                </div>
                <ol className="poc-chain__steps">
                  {(open.inspection.chain.steps || []).map((st, i) => (
                    <li key={i}>
                      {st.action || st.finding || 'step'}
                      {st.finding && st.action ? <span className="poc-chain__f"> — {st.finding}</span> : null}
                      {st.had_output && <span className="poc-chain__o"> · fed by the previous step&apos;s output</span>}
                    </li>
                  ))}
                </ol>
                <p className="poc-note">
                  One script runs these in order, each step using what the last
                  produced. You are still approving it before it runs.
                </p>
              </div>
            )}

            {open.inspection?.refine && (
              <div className={'poc-rehearsal ' + (open.inspection.refine.demonstrated
                ? 'poc-rehearsal--ok' : 'poc-rehearsal--no')}>
                <div className="poc-rehearsal__h">
                  {open.inspection.refine.demonstrated
                    ? `Rehearsed in the sandbox — demonstrated the issue in ${open.inspection.refine.iterations} attempt(s)`
                    : `Rehearsed in the sandbox — did not demonstrate it (${open.inspection.refine.stopped_because})`}
                </div>
                {open.inspection.refine.final_output && (
                  <>
                    <div className="poc-rehearsal__lbl">What the final version printed</div>
                    <pre className="poc-rehearsal__out">{open.inspection.refine.final_output}</pre>
                  </>
                )}
                <details className="poc-rehearsal__trail">
                  <summary>{(open.inspection.refine.transcript || []).length} attempt(s) — full trail</summary>
                  {(open.inspection.refine.transcript || []).map((a, i) => (
                    <div key={i} className="poc-rehearsal__step">
                      <span className="poc-rehearsal__n">#{a.iteration}</span>
                      <span className="poc-rehearsal__st">{a.status}</span>
                      {a.exit_code != null && <span className="poc-rehearsal__ex">exit {a.exit_code}</span>}
                      {a.detail && <span className="poc-rehearsal__d">{a.detail}</span>}
                    </div>
                  ))}
                </details>
                <p className="poc-note">
                  The model wrote and ran this in the isolated sandbox before you
                  saw it. You are still approving the final version — read it as
                  you would a stranger&apos;s.
                </p>
              </div>
            )}

            {open.inspection?.selection && open.inspection.selection.of?.length > 1 && (
              <p className="poc-note">
                Chose <code>{open.inspection.selection.chose}</code> from{' '}
                {open.inspection.selection.of.length} files in the repo
                {open.inspection.selection.reason ? ` — ${open.inspection.selection.reason}` : ''}.
              </p>
            )}

            {open.inspection?.vetting && !open.inspection.vetting.allowed && (
              <div className="poc-refused">
                <strong>This will not run.</strong> {open.inspection.vetting.summary}
                <ul>
                  {(open.inspection.vetting.blocking || []).map((b, i) => (
                    <li key={i}>
                      <span className="poc-signal__sev">{b.category}</span>
                      {b.line_no ? <span className="poc-signal__loc">L{b.line_no}</span> : null}
                      <span className="poc-signal__detail">{b.detail}</span>
                      {b.line && <code className="poc-signal__line">{b.line}</code>}
                    </li>
                  ))}
                </ul>
                <span className="poc-note">
                  {(open.inspection.vetting.missing || []).length
                    ? 'Approving does not override this. Either authorize the '
                      + 'capability on the engagement — if the client signed for '
                      + 'it — or rewrite the line and re-stage.'
                    : 'Scope is the authorization itself, so no setting unlocks '
                      + 'this. Rewrite the line and re-stage, or reject it.'}
                </span>
              </div>
            )}

            {signals.length > 0 && (
              <div className="poc-signals">
                {signals.map((s, i) => (
                  <div key={i} className={'poc-signal poc-signal--' + s.severity}>
                    <span className="poc-signal__sev">{s.severity}</span>
                    <span className="poc-signal__loc">{s.line_no ? `L${s.line_no}` : '—'}</span>
                    <span className="poc-signal__detail">{s.detail}</span>
                    <code className="poc-signal__line">{s.line}</code>
                  </div>
                ))}
              </div>
            )}

            <div className="poc-code-head">
              Source — read this before approving
            </div>
            <pre className="poc-code">
              {(open.code || '').split('\n').map((line, i) => (
                <div key={i} className="poc-code__row">
                  <span className="poc-code__n">{i + 1}</span>
                  <span className="poc-code__t">{line}</span>
                </div>
              ))}
            </pre>

            <div className="form-actions">
              {open.status === 'staged' && (
                <>
                  <button className="btn btn--solid" onClick={approve} disabled={busy}>
                    Approve
                  </button>
                  <button className="btn btn--danger" onClick={reject} disabled={busy}>
                    Reject
                  </button>
                </>
              )}
              {open.status === 'approved' && (
                <>
                  <button className="btn btn--solid" onClick={runPoc}
                          disabled={busy || !egressLocked
                                    || open.inspection?.vetting?.allowed === false}>
                    Run in sandbox
                  </button>
                  <button className="btn btn--danger" onClick={reject} disabled={busy}>
                    Reject
                  </button>
                </>
              )}
              {open.status === 'rejected' && <span className="poc-note">Rejected — terminal.</span>}
              {open.status === 'executed' && (
                <span className="poc-note">Executed — re-running needs a fresh decision.</span>
              )}
              {open.decided_by && (
                <span className="poc-note">decided by {open.decided_by}</span>
              )}
            </div>

            {result && (
              <div className="poc-result">
                <div className="poc-code-head">
                  Sandbox output — exit {result.exit_code ?? 'n/a'}
                  {result.timed_out ? ' · timed out' : ''} · {result.duration_s}s
                  · scope {(result.scope_hosts || []).join(', ')}
                </div>
                <pre className="poc-code">{result.stdout || '(no stdout)'}</pre>
                {result.stderr && <pre className="poc-code poc-code--err">{result.stderr}</pre>}
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
