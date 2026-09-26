import { useEffect, useState } from 'react';
import { api } from '../lib/api.js';
import { Notice } from '../components/ui.jsx';
import PocReview from '../components/PocReview.jsx';
import KnowledgeMap from '../components/KnowledgeMap.jsx';

// PoC sandbox. The isolated, scope-enforced, read-only runner
// (POST /api/sandbox/run) is wired in the sandbox milestone. The console here
// keeps the full editor + run interaction; until the runner endpoint exists,
// Run reports that it is pending.
const TYPES = ['curl', 'http-raw', 'python', 'javascript'];

export default function Sandbox() {
  const [engagements, setEngagements] = useState([]);
  const [loadError, setLoadError] = useState(null);
  const [form, setForm] = useState({ engagement_id: '', type: 'curl', target: '', code: '' });
  const [out, setOut] = useState(null);
  const [busy, setBusy] = useState(false);
  const set = (p) => setForm((f) => ({ ...f, ...p }));

  useEffect(() => {
    api.engagements.list().then((r) => {
      const items = r.items || [];
      setEngagements(items);
      if (items.length) set({ engagement_id: items[0].id });
    }).catch((e) => setLoadError(e.message));
  }, []);

  async function run() {
    setBusy(true); setOut(null);
    try {
      const r = await api.sandbox.run(form);
      setOut(r);
    } catch (e) {
      setOut({ verdict: 'error', result: e.message });
    } finally { setBusy(false); }
  }

  return (
    <div className="page">
      <Notice kind="error" message={loadError} />
      <div style={{ marginBottom: 16 }}>
        <KnowledgeMap categories={[]} confidence={out?.verdict === 'error' || out?.verdict === 'refused' ? 0 : (out ? 100 : 0)}
                      title="Sandbox" idleNote="Isolated, scope-enforced PoC runner. Run a proof below to see its request, response and verdict." />
      </div>
      <PocReview engagementId={form.engagement_id} />

      <div className="card">
        <div className="card__head"><span className="card__title">PoC sandbox</span><span className="card__meta">isolated &middot; scope-enforced &middot; read-only</span></div>
        <div className="card__body">
          <p className="intro">Re-run a generated or pasted proof-of-concept against an in-scope target inside an isolated, egress-restricted container. The engagement scope allow-list is enforced; out-of-scope targets are refused.</p>
          <div className="scan-form">
            <div className="field">
              <label className="field__label">Engagement</label>
              <div className="select-box"><select className="select" value={form.engagement_id} onChange={(e) => set({ engagement_id: e.target.value })}>
                {engagements.length === 0 && <option value="">no engagements</option>}
                {engagements.map((e) => <option key={e.id} value={e.id}>{e.target_host || e.target_url}</option>)}
              </select></div>
            </div>
            <div className="field">
              <label className="field__label">Type</label>
              <div className="select-box"><select className="select" value={form.type} onChange={(e) => set({ type: e.target.value })}>
                {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
              </select></div>
            </div>
            <div className="field">
              <label className="field__label">Target</label>
              <input className="input" placeholder="https://example.com/endpoint" value={form.target} onChange={(e) => set({ target: e.target.value })} />
            </div>
            <button className="btn btn--solid" onClick={run} disabled={busy || !form.engagement_id}>{busy ? 'Running...' : 'Run PoC'}</button>
          </div>
          <div className="field" style={{ marginTop: 12 }}>
            <label className="field__label">PoC code</label>
            <textarea className="textarea" rows={8} style={{ fontFamily: 'var(--font-mono)' }} placeholder={"curl -s 'https://example.com/?p=1'"} value={form.code} onChange={(e) => set({ code: e.target.value })}></textarea>
          </div>
        </div>
      </div>

      {out && (
        <div className="card">
          <div className="card__head"><span className="card__title">Result</span>
            <span className={'card__meta ' + (out.verdict === 'error' || out.verdict === 'refused' ? 'card__meta--warn' : out.verdict ? 'card__meta--ok' : '')}>
              {out.verdict || ''}{out.time_ms != null ? ` · ${out.time_ms} ms` : ''}
            </span>
          </div>
          <div className="card__body">
            {out.req && <><div className="io-label">Request</div><pre className="io-block">{out.req}</pre></>}
            {out.resp && <><div className="io-label">Response</div><pre className="io-block">{out.resp}</pre></>}
            {out.result && <><div className="io-label">Result</div><pre className="io-block">{out.result}</pre></>}
          </div>
        </div>
      )}
    </div>
  );
}
