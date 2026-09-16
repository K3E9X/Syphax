"""Pre-recon: the look you take *before* deciding to open an engagement.

Not to be confused with the engagement's **recon phase**, which is a different
thing and is untouched by this package. That one runs inside an authorized
engagement, drives subfinder, dnsx, httpx, gau, naabu and nmap through the
queue, and feeds the orchestrator's state machine. It is the real thing.

This is the look you take with a URL on a scoping document and no engagement
yet: where does it live, whose network is that, what is it built out of, what
else carries the same name. It exists so that opening an engagement is a
decision rather than the only way to find out.

    what                    pre-recon (this)              recon phase
    ----------------------  ----------------------------  ------------------
    when                    before an engagement exists   inside an authorized run
    authorized by           nothing - hence the budget    the engagement's attestation
    touches the target      4 paths, GET/HEAD, 6 requests as the catalog dictates
    tools                   none: DNS, RDAP, CT, 1 GET    subfinder, dnsx, httpx,
                                                          gau, naabu, nmap
    result                  a page you read               assets and fingerprints
                                                          the planner acts on

That first constraint shapes everything here. See app/prerecon/budget.py: what
reaches the target is a constant, not a judgement call.

    target.py      parse whatever was typed        (pure)
    budget.py      what pre-recon may do, as data  (pure)
    tech.py        signature table, three layers   (pure)
    summary.py     what to read first              (pure)
    dns_lookup.py  records, reverse, SPF/DMARC
    net_info.py    ASN via Team Cymru, RDAP for the netblock and the domain
    tls_info.py    the certificate, from one handshake
    ct_logs.py     names already public in Certificate Transparency
    http_probe.py  one GET of the root, plus robots/sitemap/security.txt
    run.py         all of it, concurrently, failing one section at a time
"""
from app.prerecon.run import run
from app.prerecon.target import Target, TargetError, parse

__all__ = ["run", "parse", "Target", "TargetError"]
