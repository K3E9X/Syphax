"""Public exploit references for a CVE.

When a scanner confirms a known CVE (e.g. via a nuclei CVE template - itself a
vetted public PoC), we attach links to where the operator can find deeper public
exploits. We do NOT auto-download or run untrusted raw PoCs: that is dangerous
(public exploits are unvetted, often destructive, sometimes backdoored). This
surfaces *where* the public exploit lives so a human can review it.

Pure (no network/deps) so it is unit-testable.
"""
from __future__ import annotations

import re
from typing import Dict, Optional
from urllib.parse import quote

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def normalize_cve(cve_id: str) -> Optional[str]:
    m = _CVE_RE.search(cve_id or "")
    return m.group(0).upper() if m else None


def exploit_refs(cve_id: str) -> Dict[str, str]:
    """Curated links to public exploit / advisory sources for a CVE."""
    cid = normalize_cve(cve_id)
    if not cid:
        return {}
    q = quote(cid)
    return {
        "nvd": f"https://nvd.nist.gov/vuln/detail/{cid}",
        "exploit_db": f"https://www.exploit-db.com/search?cve={cid}",
        "github_poc": f"https://github.com/search?q={q}+PoC&type=repositories",
        "metasploit": f"https://www.rapid7.com/db/?q={q}&type=metasploit",
    }


def refs_text(cve_id: str) -> str:
    refs = exploit_refs(cve_id)
    if not refs:
        return ""
    lines = "\n".join(f"  {k}: {v}" for k, v in refs.items())
    return f"Public exploit references for {normalize_cve(cve_id)}:\n{lines}"


def first_cve(cve_ids) -> Optional[str]:
    """Pick the first valid CVE id from a string or list."""
    if isinstance(cve_ids, str):
        return normalize_cve(cve_ids)
    if isinstance(cve_ids, (list, tuple)):
        for c in cve_ids:
            n = normalize_cve(str(c))
            if n:
                return n
    return None
