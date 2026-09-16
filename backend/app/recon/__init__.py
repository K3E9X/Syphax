"""Pre-engagement reconnaissance.

The view an operator opens with a URL on a scoping document and nothing else.
It answers: where does this live, who runs that network, what is it built out
of, and what else carries the same name - before any engagement exists, and
therefore before anything is authorized.

That constraint shapes everything here. See app/recon/budget.py: what reaches
the target is a constant, not a judgement call.

    target.py      parse whatever was typed        (pure)
    budget.py      what recon may do, as data      (pure)
    tech.py        signature table, three layers   (pure)
    summary.py     what to read first              (pure)
    dns_lookup.py  records, reverse, SPF/DMARC
    net_info.py    ASN via Team Cymru, RDAP for the netblock and the domain
    tls_info.py    the certificate, from one handshake
    ct_logs.py     names already public in Certificate Transparency
    http_probe.py  one GET of the root, plus robots/sitemap/security.txt
    run.py         all of it, concurrently, failing one section at a time
"""
from app.recon.run import run
from app.recon.target import Target, TargetError, parse

__all__ = ["run", "parse", "Target", "TargetError"]
