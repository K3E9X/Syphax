import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../lib/api.js';
import { Card, Empty, Metric, Notice } from '../components/ui.jsx';

/**
 * The step before an engagement.
 *
 * An operator arrives with a URL written on a scoping document and four
 * questions: where does this actually live, whose network is it on, what is it
 * built out of, and what else carries the same name. Answering them used to
 * mean opening an engagement - which is the thing that authorizes active
 * testing - just to find out whether one was worth opening.
 *
 * Everything here is passive by construction, and the page says so out loud
 * next to the button rather than in a docstring nobody reads. The list comes
 * from the backend, so it cannot promise less than the backend enforces.
 */

const LEVEL_KIND = { warn: 'warn', note: 'info', info: 'info' };

function Rows({ items }) {
  const present = (items || []).filter(([, v]) => v !== '' && v != null
    && !(Array.isArray(v) && v.length === 0));
  if (!present.length) return <Empty>Nothing returned.</Empty>;
  return (
    <dl className="kv">
      {present.map(([k, v]) => (
        <div key={k} className="rec-row">
          <dt>{k}</dt>
          <dd className="mono">{Array.isArray(v) ? v.join(', ') : String(v)}</dd>
        </div>
      ))}
    </dl>
  );
}

function NameList({ names, empty, cap = 40 }) {
  const [all, setAll] = useState(false);
  if (!names?.length) return <Empty>{empty}</Empty>;
  const shown = all ? names : names.slice(0, cap);
  return (
    <>
      <ul className="rec-names">
        {shown.map((n) => <li key={n} className="mono">{n}</li>)}
      </ul>
      {names.length > cap && (
        <button type="button" className="btn btn--muted btn--sm"
                onClick={() => setAll((x) => !x)}>
          {all ? 'Show fewer' : `Show all ${names.length}`}
        </button>
      )}
    </>
  );
}

function ScopeNotice({ scope }) {
  const [open, setOpen] = useState(false);
  if (!scope) return null;
  return (
    <div className="rec-scope">
      <button type="button" className="rec-scope__toggle" onClick={() => setOpen((o) => !o)}>
        {open ? '▾' : '▸'} Passive only — what this sends, exactly
      </button>
      {open && (
        <div className="rec-scope__body">
          <div>
            <strong>Reaches the target</strong>
            <ul>{scope.touches_target.map((x) => <li key={x} className="mono">{x}</li>)}</ul>
          </div>
          <div>
            <strong>Asks third parties</strong>
            <ul>{scope.asks_third_parties.map((x) => <li key={x}>{x}</li>)}</ul>
          </div>
          <div>
            <strong>Never</strong>
            <ul>{scope.never.map((x) => <li key={x}>{x}</li>)}</ul>
          </div>
          <div>
            <strong>Limits</strong>
            <ul>{scope.limits.map((x) => <li key={x}>{x}</li>)}</ul>
          </div>
        </div>
      )}
    </div>
  );
}

function TechColumn({ title, note, items }) {
  return (
    <div className="rec-tech__col">
      <div className="rec-tech__h">{title}<small>{note}</small></div>
      {!items?.length && <Empty>Nothing identified.</Empty>}
      {items?.map((t) => (
        <div key={t.name + t.evidence} className="rec-tech__item" title={t.evidence}>
          <span className="rec-tech__name">
            {t.name}{t.version ? <span className="rec-tech__v"> {t.version}</span> : null}
          </span>
          <span className={'rec-tech__c rec-tech__c--' + t.confidence}>{t.confidence}</span>
          <span className="rec-tech__cat">{t.category}</span>
          {t.note && <span className="rec-tech__note">{t.note}</span>}
        </div>
      ))}
    </div>
  );
}

export default function Recon() {
  const nav = useNavigate();
  const [target, setTarget] = useState('');
  const [includeCt, setIncludeCt] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [report, setReport] = useState(null);
  const [scope, setScope] = useState(null);

  useEffect(() => {
    // A failure here costs the disclosure panel and nothing else, so it does
    // not get an error surface of its own - but it must not be swallowed
    // either, or the panel silently disappears.
    api.recon.scope().then(setScope).catch((e) => setError((prev) => prev || e.message));
  }, []);

  const run = useCallback(async (e) => {
    e?.preventDefault();
    if (!target.trim() || busy) return;
    setBusy(true);
    setError('');
    try {
      setReport(await api.recon.run(target.trim(), includeCt));
    } catch (err) {
      setError(err.message);
      setReport(null);
    } finally {
      setBusy(false);
    }
  }, [target, includeCt, busy]);

  function toEngagement() {
    // Carried as router state rather than a query string: the scope list can be
    // two hundred hostnames, and a URL is the wrong place for them.
    nav('/engagements', {
      state: {
        target_url: report.target.base_url,
        scope_hosts: (report.candidate_hosts || []).join(', '),
        from_recon: report.target.host,
      },
    });
  }

  const t = report?.target;
  const dns = report?.dns || {};
  const asn = report?.network?.asn || {};
  const reg = report?.network?.registration || {};
  const domain = report?.domain || {};
  const tls = report?.tls || {};
  const http = report?.http || {};
  const root = http.root || {};
  const headers = report?.headers || {};
  const tech = report?.technologies || {};
  const ct = report?.certificate_transparency || {};
  const files = report?.public_files || {};
  const counts = report?.counts || {};

  return (
    <div className="page">
      <form className="rec-bar" onSubmit={run}>
        <input
          className="input rec-bar__input"
          placeholder="example.com, https://app.example.com:8443, or 1.2.3.4"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          autoCapitalize="none"
          spellCheck="false"
          aria-label="Target"
        />
        <label className="rec-bar__ct" title="Certificate Transparency: the slowest source, and the one most likely to be rate-limiting">
          <input type="checkbox" checked={includeCt}
                 onChange={(e) => setIncludeCt(e.target.checked)} />
          <span>CT logs</span>
        </label>
        <button className="btn btn--solid" type="submit" disabled={!target.trim() || busy}>
          {busy ? 'Looking…' : 'Run recon'}
        </button>
      </form>

      <ScopeNotice scope={scope} />
      <Notice kind="error" message={error} />

      {!report && !busy && !error && (
        <Card title="Before the engagement">
          <p className="home-intro">
            Point this at a target and it answers the four questions worth asking
            before you open an engagement: where it actually lives, whose network
            that is, what it is built out of, and what else carries the same name.
          </p>
          <p className="home-intro">
            Nothing here is an authorized test. It asks public infrastructure about
            the target — DNS, the registries, Certificate Transparency — and makes
            the same handful of requests a browser makes when you type the URL.
            Active testing needs an engagement, which is where the authorization
            lives.
          </p>
        </Card>
      )}

      {report && (
        <>
          <div className="rec-head">
            <div className="rec-head__target">
              <span className="rec-head__host mono">{t.host}</span>
              <span className="rec-head__meta mono">
                {t.base_url}{t.registrable_domain && t.registrable_domain !== t.host
                  ? ` · ${t.registrable_domain}` : ''} · {report.took_ms} ms
              </span>
            </div>
            <button className="btn btn--solid" type="button" onClick={toEngagement}>
              Create an engagement with this target
            </button>
          </div>

          {(t.notes || []).map((n) => (
            <Notice key={n} kind="info" message={n} />
          ))}

          <div className="stats">
            <Metric label="addresses" value={counts.addresses ?? 0} />
            <Metric label="technologies" value={counts.technologies ?? 0} />
            <Metric label="cert names" value={counts.certificate_names ?? 0} />
            <Metric label="names in CT" value={counts.names_in_ct ?? 0} />
            <Metric label="missing headers" value={counts.missing_headers ?? 0}
                    kind={counts.missing_headers ? 'warn' : ''} />
          </div>

          {!!report.highlights?.length && (
            <Card title="Read this first">
              {report.highlights.map((h, i) => (
                <div key={i} className={'rec-hl rec-hl--' + LEVEL_KIND[h.level]}>
                  <span className="rec-hl__t">{h.text}</span>
                  {h.why && <span className="rec-hl__w">{h.why}</span>}
                </div>
              ))}
            </Card>
          )}

          {!!report.errors?.length && (
            <Notice kind="warn" title="Some sources did not answer"
                    message={report.errors.map((e) => `${e.section}: ${e.error}`).join(' · ')} />
          )}

          <div className="set-grid">
            <Card title="Network" meta={asn.shared_infrastructure ? 'shared infrastructure' : ''}
                  metaClass={asn.shared_infrastructure ? 'card__meta--warn' : ''}>
              <Rows items={[
                ['Primary address', report.network?.primary_address],
                ['All addresses', dns.addresses],
                ['Reverse DNS', Object.entries(dns.reverse || {})
                  .filter(([, v]) => v).map(([k, v]) => `${k} → ${v}`)],
                ['ASN', asn.asn ? `AS${asn.asn}` : ''],
                ['Network owner', asn.as_name],
                ['Announced prefix', asn.prefix],
                ['Country', asn.country || reg.country],
                ['Registry', asn.registry],
                ['Netblock', reg.range],
                ['Netblock name', reg.name],
                ['Organisations', reg.organisations],
              ]} />
            </Card>

            <Card title="DNS">
              <Rows items={[
                ...Object.entries(dns.records || {}).map(([k, v]) => [k, v]),
                ['SPF', dns.spf],
                ['DMARC', dns.dmarc],
              ]} />
            </Card>

            <Card title="Domain registration"
                  meta={domain.dnssec ? 'DNSSEC signed' : ''}>
              {t.is_ip
                ? <Empty>The target is an address; there is no domain to look up.</Empty>
                : <Rows items={[
                  ['Registrar', domain.registrar],
                  ['Registered', domain.registered],
                  ['Expires', domain.expires],
                  ['Last changed', domain.changed],
                  ['Status', domain.status],
                  ['Nameservers', domain.nameservers],
                  ['DNSSEC', domain.dnssec === undefined ? '' : String(domain.dnssec)],
                ]} />}
            </Card>

            <Card title="TLS certificate"
                  meta={tls.available ? `${tls.days_remaining} days left` : 'not available'}
                  metaClass={tls.available && tls.days_remaining < 30 ? 'card__meta--warn' : ''}>
              {!tls.available
                ? <Empty>{tls.error || 'No certificate could be read.'}</Empty>
                : (
                  <>
                    <Rows items={[
                      ['Subject', tls.subject],
                      ['Issuer', tls.issuer_org || tls.issuer],
                      ['Valid from', tls.not_before],
                      ['Valid to', tls.not_after],
                      ['Signature', tls.signature_algorithm],
                      ['Key size', tls.key_bits],
                      ['Protocol', `${tls.tls_version || ''} ${tls.cipher || ''}`.trim()],
                      ['SHA-256', tls.fingerprint_sha256],
                    ]} />
                    {!!tls.issues?.length && (
                      <Notice kind="warn" message={tls.issues.join(' · ')} />
                    )}
                    <div className="io-label">Names on the certificate ({tls.san_count})</div>
                    <NameList names={tls.san} empty="No subject alternative names." />
                  </>
                )}
            </Card>

            <Card className="set-full" title="Technology"
                  meta="three layers, because they answer three different questions">
              <div className="rec-tech">
                <TechColumn title="Frontend" note="runs in the browser"
                            items={tech.frontend} />
                <TechColumn title="Backend" note="runs on the server"
                            items={tech.backend} />
                <TechColumn title="Infrastructure" note="sits in front"
                            items={tech.infrastructure} />
              </div>
            </Card>

            <Card title="HTTP" meta={root.status ? `${root.status} ${root.reason || ''}` : 'no answer'}>
              {http.error && <Notice kind="warn" message={http.error} />}
              <Rows items={[
                ['Final URL', root.url],
                ['Title', root.title],
                ['Protocol', root.http_version],
                ['Response time', root.elapsed_ms ? `${root.elapsed_ms} ms` : ''],
                ['Body size', root.body_bytes ? `${root.body_bytes} bytes` : ''],
                ['Requests made', http.requests_made],
              ]} />
              {!!http.redirects?.length && (
                <>
                  <div className="io-label">Redirect chain</div>
                  <ol className="rec-redirects">
                    {http.redirects.map((r, i) => (
                      <li key={i} className="mono">{r.status} → {r.to}</li>
                    ))}
                  </ol>
                </>
              )}
            </Card>

            <Card title="Security headers"
                  meta={headers.missing ? `${headers.missing.length} missing` : ''}
                  metaClass={headers.missing?.length ? 'card__meta--warn' : ''}>
              {!headers.present && !headers.missing && (
                <Empty>Nothing answered, so there are no headers to review.</Empty>
              )}
              {!!headers.present?.length && (
                <>
                  <div className="io-label">Present</div>
                  {headers.present.map((h) => (
                    <div key={h.name} className="rec-hdr">
                      <span className="rec-hdr__n mono">{h.name}</span>
                      <span className="rec-hdr__v mono">{h.value}</span>
                    </div>
                  ))}
                </>
              )}
              {!!headers.missing?.length && (
                <>
                  <div className="io-label">Missing, and what that costs</div>
                  {headers.missing.map((h) => (
                    <div key={h.name} className="rec-hdr rec-hdr--missing">
                      <span className="rec-hdr__n mono">{h.name}</span>
                      <span className="rec-hdr__why">{h.consequence}</span>
                    </div>
                  ))}
                </>
              )}
              {!!headers.disclosing?.length && (
                <>
                  <div className="io-label">Disclosing a version</div>
                  {headers.disclosing.map((h) => (
                    <div key={h.name} className="rec-hdr">
                      <span className="rec-hdr__n mono">{h.name}</span>
                      <span className="rec-hdr__v mono">{h.value}</span>
                    </div>
                  ))}
                </>
              )}
            </Card>

            <Card title="Cookies" meta="set before any login">
              {!report.cookies?.length
                ? <Empty>The root response set no cookies.</Empty>
                : (
                  <table className="tbl">
                    <thead><tr><th>Name</th><th>HttpOnly</th><th>Secure</th><th>SameSite</th></tr></thead>
                    <tbody>
                      {report.cookies.map((c) => (
                        <tr key={c.name}>
                          <td className="mono">{c.name}</td>
                          <td className={c.http_only ? 'ok' : 'bad'}>{c.http_only ? 'yes' : 'no'}</td>
                          <td className={c.secure ? 'ok' : 'bad'}>{c.secure ? 'yes' : 'no'}</td>
                          <td className="mono">{c.same_site}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
            </Card>

            <Card title="Public files" meta="robots, sitemap, security.txt">
              {Object.entries(files).map(([path, info]) => (
                <div key={path} className="rec-file">
                  <div className="rec-file__h">
                    <span className="mono">{path}</span>
                    <span className={'rec-file__s ' + (info.present ? 'ok' : 'unset')}>
                      {info.error || (info.present ? `${info.bytes} bytes` : `${info.status}`)}
                    </span>
                  </div>
                  {info.present && <pre className="rec-file__p">{info.preview}</pre>}
                </div>
              ))}
              {!Object.keys(files).length && <Empty>Not fetched.</Empty>}
            </Card>

            <Card className="set-full" title="Names in Certificate Transparency"
                  meta={ct.available ? `${ct.total} distinct` : (ct.reason || 'not queried')}>
              {!ct.available
                ? <Empty>{ct.reason || 'Certificate Transparency was not queried.'}</Empty>
                : (
                  <>
                    <p className="home-intro">
                      Published by the CAs themselves, not discovered by touching
                      anything. Names here that are not on the scoping document are
                      the conversation to have now.
                    </p>
                    {!!ct.wildcards?.length && (
                      <div className="io-label">Wildcards: <span className="mono">{ct.wildcards.join(', ')}</span></div>
                    )}
                    <NameList names={ct.names} empty="No names found." cap={60} />
                  </>
                )}
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
