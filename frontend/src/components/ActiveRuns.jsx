import { useCallback, useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { api } from '../lib/api.js';
import { rememberEngagement } from '../lib/useApi.js';

/**
 * "A run is going on, here it is."
 *
 * A run lives in the orchestrator worker, not in the browser: it survives a
 * page change, a logout, a closed laptop, a different machine. Nothing said so,
 * and the remembered engagement lives in localStorage, which does not travel.
 * So an operator who came back from elsewhere had no way to find the run they
 * had started - it looked like it had been lost.
 *
 * Polls the server (the only thing that knows), so it is correct from any
 * session. Hidden when nothing is running, and on the Live view itself, where
 * the run is already on screen.
 */
export default function ActiveRuns() {
  const [runs, setRuns] = useState([]);
  const [err, setErr] = useState(null);
  const navigate = useNavigate();
  const { pathname } = useLocation();

  const load = useCallback(() => {
    api.engagements.activeRuns()
      .then((r) => { setRuns(r.items || []); setErr(null); })
      // Quiet, but never silent: swallowing this would make "nothing is
      // running" and "I cannot tell you what is running" look identical, which
      // is the worst answer for the question this banner exists to answer.
      .catch((e) => { setRuns([]); setErr(e.message); });
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, [load, pathname]);

  if (pathname.startsWith('/live')) return null;
  if (err) {
    return (
      <div className="active-runs" role="status">
        <div className="active-runs__item active-runs__item--err">
          <span>Could not check for runs in progress — {err}</span>
          <button type="button" className="active-runs__cta" onClick={load}>retry</button>
        </div>
      </div>
    );
  }
  if (!runs.length) return null;

  function resume(r) {
    rememberEngagement(r.engagement_id);
    navigate('/live');
  }

  return (
    <div className="active-runs" role="status">
      {runs.map((r) => (
        <button key={r.run_id} type="button" className="active-runs__item"
                onClick={() => resume(r)}
                title="Open the live view for this run">
          <span className="active-runs__dot" />
          <b>{r.target}</b>
          <span className="active-runs__meta">
            {r.status}{r.phase ? ` · ${r.phase}` : ''}
            {r.jobs_launched ? ` · ${r.jobs_launched} jobs` : ''}
            {r.stop_requested ? ' · stopping' : ''}
          </span>
          <span className="active-runs__cta">resume →</span>
        </button>
      ))}
    </div>
  );
}
