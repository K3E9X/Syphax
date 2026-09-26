import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../lib/api.js';
import { useApi } from '../lib/useApi.js';
import { Notice, UsageRow, fmtTokens, fmtUsd } from '../components/ui.jsx';
import { COV_AXES, Donut, Histogram, Legend, Radar, SEV_HEX } from '../components/Charts.jsx';
import KnowledgeMap from '../components/KnowledgeMap.jsx';
import { mapFromEngagements } from '../lib/knowledgeMap.js';

const PHASE_ORDER = ['Reconnaissance', 'Scanning & enumeration', 'Exploitation', 'Capture & analysis', 'Other'];
const LLM_ROLES = ['planner', 'executor', 'validator'];
const ROLE_HEX = { planner: '#c2410c', executor: '#a78bfa', validator: '#34d399' };
const SEV_BARS = ['critical', 'high', 'medium', 'low', 'info'];

export default function Home() {
  const navigate = useNavigate();
  // These four used to be `.then(set).catch(() => {})`. A dead backend, a
  // wrong API key or a refused VPN all rendered as "-" with no explanation,
  // which for a security tool is the worst failure mode there is: "I see no
  // findings" must never look like "the API is down".
  const cfg = useApi(() => api.config(), []);
  const dashboard = useApi(() => api.dashboard(), []);
  const toolList = useApi(() => api.tools(), [], { initial: [] });
  const config = cfg.data;
  const dash = dashboard.data;
  const tools = Array.isArray(toolList.data) ? toolList.data : [];
  const loadError = cfg.error || dashboard.error || toolList.error;

  const [pinging, setPinging] = useState(false);
  const [pings, setPings] = useState([]);
  const [net, setNet] = useState(null);
  const [proxyUrl, setProxyUrl] = useState('');
  const [vpnPath, setVpnPath] = useState('');
  const [vpnMode, setVpnMode] = useState('wireguard');
  const [netBusy, setNetBusy] = useState(false);
  const [netError, setNetError] = useState(null);
  const [ident, setIdent] = useState(null);
  const [guard, setGuard] = useState(null);

  useEffect(() => {
    refreshIdentity();
     
  }, []);

  // Ping every role, not just the planner: they can sit on different
  // providers, so one answering says nothing about the other two.
  async function testLlm() {
    setPinging(true);
    setPings(LLM_ROLES.map((role) => ({ role, state: 'pending' })));
    const results = await Promise.all(
      LLM_ROLES.map(async (role) => {
        try {
          const r = await api.llmPing(role);
          return {
            role,
            state: 'ok',
            model: r.model_used,
            latency: r.latency_ms,
            tokens: (r.prompt_tokens || 0) + (r.completion_tokens || 0),
            fallback: r.fallback_used,
            reply: r.reply,
          };
        } catch (e) {
          return { role, state: 'err', error: e.message };
        }
      })
    );
    setPings(results);
    setPinging(false);
  }

  // One call chain, used both before bringing a tunnel up and after, so the
  // two readings are directly comparable.
  const refreshIdentity = async () => {
    const [i, g, s] = await Promise.allSettled([
      api.network.identity(), api.network.guard(), api.network.status(),
    ]);
    if (i.status === 'fulfilled') setIdent(i.value);
    if (g.status === 'fulfilled') setGuard(g.value);
    if (s.status === 'fulfilled') setNet(s.value);
  };

  async function refreshNetwork() {
    setNetBusy(true);
    setNetError(null);
    try {
      const r = await api.network.check();
      if (!r.safe && r.reason) setNetError(r.reason);
      await refreshIdentity();
    } catch (e) {
      setNetError(e.message);
    }
    setNetBusy(false);
  }

  // Startup records the real IP automatically, but an operator whose tunnel
  // was already up when the stack started would have a "real" IP that is
  // already the tunnel's - which silently defeats the kill switch, since that
  // is the value it compares against.
  async function setBaseline() {
    setNetBusy(true);
    setNetError(null);
    try {
      await api.network.setBaseline();
      await refreshIdentity();
    } catch (e) {
      setNetError(e.message);
    }
    setNetBusy(false);
  }

  async function applyProxy() {
    setNetBusy(true);
    setNetError(null);
    try {
      setNet(await api.network.setProxy(proxyUrl));
      await refreshIdentity();
      setProxyUrl('');
    } catch (e) {
      setNetError(e.message);
    }
    setNetBusy(false);
  }

  async function connectVpn() {
    setNetBusy(true);
    setNetError(null);
    try {
      setNet(await api.network.connectVpn(vpnPath, vpnMode));
      await refreshIdentity();
    } catch (e) {
      setNetError(e.message);
    }
    setNetBusy(false);
  }

  async function dropTunnel() {
    setNetBusy(true);
    setNetError(null);
    try {
      setNet(await api.network.disconnect());
      await refreshIdentity();
    } catch (e) {
      setNetError(e.message);
    }
    setNetBusy(false);
  }

  const roles = config?.llm_roles || {};
  const usage = dash?.llm_usage || { calls: 0, total_tokens: 0, cost_usd: 0, by_model: [] };
  const conf = dash?.confirmed_findings || {};
  const confTotal = Object.values(conf).reduce((a, b) => a + b, 0);

  // Chart data. The engagement list carries a per-engagement coverage radar;
  // averaging them gives a fleet-wide "what have we actually tested" view.
  const engList = useApi(() => api.engagements.list(), []);
  const engItems = engList.data?.items || [];
  const aggRadar = COV_AXES.map((_, i) => {
    const vals = engItems.map((e) => (e.radar || [])[i]).filter((v) => typeof v === 'number');
    return vals.length ? Math.round(vals.reduce((a, b) => a + b, 0) / vals.length) : 0;
  });
  const sevSegments = SEV_BARS
    .map((s) => ({ label: s, value: conf[s] || 0, color: SEV_HEX[s] }))
    .filter((s) => s.value > 0);
  const roleBars = (usage.by_role || [])
    .map((r) => ({ label: r.role, value: Math.round((r.tokens || 0) / 1000), color: ROLE_HEX[r.role] || '#c2410c' }));

  // Fleet knowledge map (shared derivation, also used by Engagements).
  const { categories: kmCats, confidence: kmConfidence } = mapFromEngagements(engItems);

  const byPhase = {};
  for (const t of tools) (byPhase[t.phase] = byPhase[t.phase] || []).push(t);
  const phases = PHASE_ORDER.filter((p) => byPhase[p]);
  const okTools = tools.filter((t) => t.available).length;

  const budget = dash?.budget;

  return (
    <div className="page">
      <h1 className="sr-only">Dashboard</h1>
      <Notice kind="error" title="Backend unreachable" message={loadError}
              onRetry={() => { cfg.reload(); dashboard.reload(); toolList.reload(); }} />
      {budget?.over && (
        <Notice kind="error" title="LLM budget exceeded"
                message={`$${(budget.month_spend_usd || 0).toFixed(2)} spent this month against a $${(budget.monthly_limit_usd || 0).toFixed(2)} limit (${budget.pct || 0}%). Raise or clear the limit in Settings.`} />
      )}
      {budget && !budget.priced && (usage.total_tokens > 0) && (
        <Notice kind="warn" title="Spend is not being measured"
                message={`${((usage.total_tokens || 0) / 1e6).toFixed(2)}M tokens used but LLM_PRICING is unset, so every model is costed at $0. Set it in .env to get a real figure.`} />
      )}

      {kmCats.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <KnowledgeMap categories={kmCats} confidence={kmConfidence}
                        title="Engagements map"
                        subtitle={`${engItems.length} engagement(s) · avg coverage ${kmConfidence}% · click to open live view`}
                        metricLabel="coverage"
                        onSelect={(id) => navigate(`/engagements/${id}/live`)} />
        </div>
      )}

      <div className="metrics">
        <Link className="metric metric--link" to="/engagements">
          <div className="metric__l">Active engagements</div>
          <div className="metric__v">{dash?.active_engagements ?? '-'}</div>
          <div className="metric__sub">authorized →</div>
        </Link>
        <Link className="metric metric--link metric--ok" to="/scans">
          <div className="metric__l">Jobs running</div>
          <div className="metric__v">{dash?.running_jobs ?? '-'}</div>
          <div className="metric__sub">queued + running →</div>
        </Link>
        <Link className="metric metric--link metric--alert" to="/findings">
          <div className="metric__l">Confirmed findings</div>
          <div className="metric__v">{confTotal}</div>
          <div className="metric__sub">{conf.critical || 0} critical &middot; {conf.high || 0} high →</div>
        </Link>
        <Link className="metric metric--link" to="/settings">
          <div className="metric__l">API spend</div>
          <div className="metric__v"><small>$</small>{(usage.cost_usd || 0).toFixed(2)}</div>
          <div className="metric__sub">
            {((usage.total_tokens || 0) / 1e6).toFixed(2)}M tokens &middot; {usage.calls} calls
            {budget?.monthly_limit_usd ? ` · ${budget.pct}% of budget` : ''}
          </div>
        </Link>
      </div>

      <div className="card">
        <div className="card__head"><span className="card__title">Analytics</span><span className="card__meta">confirmed findings · testing coverage · LLM spend</span></div>
        <div className="card__body">
          <div className="viz-row">
            <div className="viz">
              <div className="viz__h">Confirmed findings by severity</div>
              <div className="viz__body">
                {confTotal > 0 ? (
                  <>
                    <Donut segments={sevSegments} centerLabel="confirmed" />
                    <Legend segments={sevSegments} />
                  </>
                ) : <div className="empty">No confirmed findings yet.</div>}
              </div>
            </div>

            <div className="viz">
              <div className="viz__h">Testing coverage (fleet avg)</div>
              <div className="viz__body" style={{ flexDirection: 'column' }}>
                {engItems.length > 0 ? (
                  <>
                    <Radar values={aggRadar} axes={COV_AXES} />
                    <div className="radar-axes">
                      {COV_AXES.map((a, i) => <span key={a}>{a} <b>{aggRadar[i]}%</b></span>)}
                    </div>
                  </>
                ) : <div className="empty">No engagements yet.</div>}
              </div>
            </div>

            <div className="viz">
              <div className="viz__h">LLM tokens by role (k)</div>
              <div className="viz__body" style={{ width: '100%' }}>
                {roleBars.length > 0
                  ? <Histogram data={roleBars} />
                  : <div className="empty">No LLM calls yet.</div>}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="dash-grid">
        <div>
          <div className="card">
            <div className="card__head"><span className="card__title">Backend status</span></div>
            <div className="card__body">
              <dl className="kv">
                <dt>LLM configured</dt><dd className={config?.llm_configured ? 'kv-yes' : ''}>{config?.llm_configured ? 'yes' : 'no'}</dd>
                <dt>Model router</dt>
                <dd className="mono">
                  {Object.keys(roles).length
                    ? Object.entries(roles).map(([r, v]) => `${r}: ${(v && v.model) || v}`).join('  ·  ')
                    : (config?.llm_model || '-')}
                </dd>
                <dt>MITM proxy</dt><dd className="mono kv-yes">:{config?.mitm_port ?? '-'} listening</dd>
                <dt>Data directory</dt><dd className="mono">{config?.data_dir || '-'}</dd>
              </dl>
            </div>
          </div>

          <div className="card">
            <div className="card__head">
              <span className="card__title">Spend by role</span>
              <span className="card__meta">{fmtTokens(usage.total_tokens)} tokens</span>
            </div>
            <div className="card__body">
              {/* Which part of the system is spending, not just which model.
                  Two roles often share a model, and the planner is re-invoked
                  on every loop iteration - so this is where a runaway run
                  shows up first. */}
              <div className="usage">
                {(usage.by_role || []).length === 0 && <div className="empty">No LLM calls yet.</div>}
                {(usage.by_role || []).map((r) => (
                  <UsageRow key={r.role} label={r.role} pct={r.pct}
                            value={fmtTokens(r.tokens)}
                            title={`${r.calls} call(s) · ${fmtUsd(r.cost_usd, 4)} · ${r.pct}% of all tokens`} />
                ))}
              </div>
              {usage.total_tokens > 0 && (
                <div className="tok__legend" style={{ marginTop: 8 }}>
                  <span><i className="tok__dot tok__dot--prompt" />prompt <b>{usage.prompt_pct ?? 0}%</b></span>
                  <span><i className="tok__dot tok__dot--completion" />completion <b>{100 - (usage.prompt_pct ?? 0)}%</b></span>
                </div>
              )}
            </div>
          </div>

          <div className="card">
            <div className="card__head"><span className="card__title">Model usage</span><span className="card__meta">${(usage.cost_usd || 0).toFixed(2)}</span></div>
            <div className="card__body">
              <div className="usage">
                {(usage.by_model || []).length === 0 && <div className="empty">No LLM calls yet.</div>}
                {(usage.by_model || []).map((m) => (
                  <div key={m.model} className="usage__row">
                    <span className="usage__l">{m.model}</span>
                    <span className="usage__bar"><span className="usage__fill" style={{ width: m.pct + '%' }}></span></span>
                    <span className="usage__n">{(m.tokens / 1000).toFixed(0)}k</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card__head">
              <span className="card__title">Exit route</span>
              <span className={'card__meta ' + (net?.mode !== 'off' && !net?.ip_changed ? 'kv-no' : '')}>
                {net?.mode === 'off' ? 'direct connection' : net?.mode || '-'}
              </span>
            </div>
            <div className="card__body">
              {/* Before / after, side by side. The point of the card is the
                  comparison: check once before bringing a tunnel up, once
                  after, and see whether anything actually changed. */}
              <div className="ident">
                <div className="ident__col">
                  <div className="ident__l">Your real IP</div>
                  <div className="ident__v mono">{ident?.real_ip || net?.baseline_ip || '—'}</div>
                  <div className="ident__sub">recorded with no tunnel</div>
                </div>
                <div className={'ident__arrow' + (ident?.ip_changed ? ' ident__arrow--ok' : '')}>→</div>
                <div className="ident__col">
                  <div className="ident__l">Exit IP now</div>
                  <div className={'ident__v mono' + (ident?.ip_changed ? ' kv-yes' : '')}>
                    {ident?.exit_ip || net?.current_ip || '—'}
                  </div>
                  <div className="ident__sub">
                    {ident?.mode === 'off' ? 'direct connection' : `via ${ident?.mode || net?.mode || '-'}`}
                  </div>
                </div>
              </div>

              {ident && ident.mode !== 'off' && !ident.ip_changed && (
                <Notice kind="warn" message="Same IP on both sides: traffic is NOT going through the tunnel. Scans run from your real IP unless REQUIRE_VPN is on, in which case they are blocked." />
              )}
              {ident && ident.mode === 'off' && (
                <p className="ident__note">
                  No tunnel configured — scans go out from your real IP.
                </p>
              )}

              {/* What the target actually sees, generated the same way a real
                  job generates it, so in rotate mode this is a real sample. */}
              {ident?.headers && (
                <>
                  <div className="ident__hdr-title">
                    Headers a scan would send · UA mode {ident.user_agent_mode}
                  </div>
                  <pre className="ident__hdrs">
                    {Object.entries(ident.headers).map(([k, v]) => `${k}: ${v}`).join('\n')}
                  </pre>
                </>
              )}

              <dl className="kv">
                <dt>Block scans without VPN</dt>
                <dd className={net?.require_vpn ? 'kv-yes' : ''}>{net?.require_vpn ? 'yes' : 'no'}</dd>
                <dt>Scan allowed now</dt>
                <dd className={guard?.allowed ? 'kv-yes' : 'kv-no'}>
                  {guard ? (guard.allowed ? 'yes' : `no — ${guard.reason}`) : '—'}
                </dd>
                {/* A tunnel can carry the traffic while name lookups still go
                    to the host resolver in cleartext. Say which it is. */}
                {net?.mode && net.mode !== 'off' && (
                  <>
                    <dt>Target DNS via tunnel</dt>
                    <dd className={net.dns_through_tunnel ? 'kv-yes' : 'kv-no'}>
                      {net.dns_through_tunnel
                        ? `yes — ${(net.dns_pinned_hosts || []).length} internal host(s) pinned`
                        : 'no — lookups leak to the host resolver'}
                    </dd>
                  </>
                )}
              </dl>

              <div className="key-row" style={{ marginTop: 8 }}>
                <input
                  className="input"
                  placeholder="socks5://127.0.0.1:9050"
                  value={proxyUrl}
                  onChange={(e) => setProxyUrl(e.target.value)}
                />
                <button className="btn btn--solid" onClick={applyProxy} disabled={!proxyUrl || netBusy}>Route</button>
              </div>

              <div className="key-row" style={{ marginTop: 6 }}>
                <input
                  className="input"
                  placeholder="/data/vpn/wg0.conf  (blank = VPN_CONFIG_PATH)"
                  value={vpnPath}
                  onChange={(e) => setVpnPath(e.target.value)}
                />
                <div className="select-box">
                  <select className="select" value={vpnMode} onChange={(e) => setVpnMode(e.target.value)}>
                    <option value="wireguard">WireGuard</option>
                    <option value="openvpn">OpenVPN</option>
                  </select>
                </div>
                <button className="btn btn--solid" onClick={connectVpn} disabled={netBusy}>Connect</button>
              </div>
              <div className="form-actions" style={{ marginTop: 6 }}>
                <button className="btn" onClick={refreshNetwork} disabled={netBusy}>{netBusy ? 'Checking...' : 'Check IP'}</button>
                <button className="btn" onClick={setBaseline} disabled={netBusy} title="Record the current IP as your real one. Use before connecting a tunnel.">This is my real IP</button>
                <button className="btn" onClick={dropTunnel} disabled={netBusy}>Direct</button>
              </div>
              {netError && <Notice kind="error" message={netError} />}
              <p className="home-intro" style={{ marginTop: 8 }}>
                Turn this on before creating an engagement. A proxy needs no privileges;
                for WireGuard/OpenVPN set VPN_CONFIG_PATH in .env.
              </p>
            </div>
          </div>

          <div className="card">
            <div className="card__head"><span className="card__title">LLM sanity check</span><span className="card__meta">all roles</span></div>
            <div className="card__body">
              <p className="home-intro">Send a tiny request to each role's provider to verify the key, the model and how slow it answers.</p>
              <button className="btn btn--solid" onClick={testLlm} disabled={pinging}>{pinging ? 'Pinging...' : 'Ping LLM'}</button>
              {pings.map((p) => (
                <p key={p.role} className={'ping-result ping-result--' + p.state}>
                  <strong>{p.role}</strong>{' '}
                  {p.state === 'pending' && 'pinging...'}
                  {p.state === 'ok' && `${p.model} · ${p.latency}ms${p.tokens ? ` · ${p.tokens} tok` : ''}${p.fallback ? ' · fallback' : ''}`}
                  {p.state === 'err' && p.error}
                </p>
              ))}
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card__head"><span className="card__title">Toolchain / SBOM</span><span className="card__meta">{okTools}/{tools.length} available &middot; container image</span></div>
          <div className="card__body" style={{ paddingTop: 4 }}>
            {phases.length === 0 && <div className="empty">Loading tools...</div>}
            {phases.map((p) => (
              <div key={p} className="sbom-phase">
                <div className="sbom-phase__t">{p}</div>
                <table className="sbom">
                  <tbody>
                    {byPhase[p].map((t) => (
                      <tr key={t.name}>
                        <td className="sbom__name">{t.name}</td>
                        <td className="sbom__ver">{t.version ? 'v' + t.version : '-'}</td>
                        <td className="sbom__src">{t.source}</td>
                        <td className={t.available ? 'sbom__ok' : 'sbom__missing'}>{t.available ? 'ready' : 'missing'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
