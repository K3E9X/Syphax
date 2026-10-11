"""s3scanner: open object storage, across six providers, anonymously.

cloud_enum already permutes the brand name against AWS S3, Azure blob and
Google Cloud Storage. s3scanner answers the same question with two
differences that make it worth its (small) place in the image:

  * SIX providers, not three - AWS, GCP, DigitalOcean Spaces, Linode,
    Scaleway and DreamHost. A team that moved off S3 to Spaces or Scaleway is
    exactly the team whose bucket nobody re-reviewed, and nothing here looked
    there at all.
  * it reports the PERMISSIONS it observed, per bucket, rather than only that
    the name resolves. "AllUsers: READ, WRITE" is a different finding from
    "the bucket exists", and the severity follows: a world-WRITABLE bucket is
    an inbound code path into whatever consumes it.

Anonymous only. s3scanner's own README is explicit that non-AWS providers are
checked for anonymous permissions, and we pass no credentials for any of
them: this is reconnaissance against public configuration, not authenticated
enumeration of someone's account.

Output is one JSON object per line (`-json`), so a malformed line costs one
bucket rather than the scan.
"""
from __future__ import annotations

from typing import Any, Dict, List, Sequence
from urllib.parse import urlparse

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult, iter_json_lines

# What an ACL grant means for the report. s3scanner reports per-permission
# grants for AllUsers (anonymous) and AuthUsers (any cloud account).
_ANON = "allusers"
_AUTH = "authusers"

MAX_FINDINGS = 60


def _label(value: Any) -> str:
    return str(value or "").strip().lower()


def permissions_of(entry: Dict[str, Any]) -> Dict[str, List[str]]:
    """{"allusers": ["read", "write"], "authusers": [...]} from one record.

    s3scanner has used a few shapes across versions: a `permissions` map, and
    flat `perm_*` keys. Both are read, because a wrapper that only understands
    the shape in front of it today reports nothing after the next upgrade -
    which is how two tools in this image failed silently for a month.
    """
    out: Dict[str, List[str]] = {_ANON: [], _AUTH: []}
    perms = entry.get("permissions")
    if isinstance(perms, dict):
        for who, granted in perms.items():
            key = _ANON if "all" in _label(who) else _AUTH
            if isinstance(granted, dict):
                out[key].extend(sorted(k.lower() for k, v in granted.items() if v))
            elif isinstance(granted, list):
                out[key].extend(sorted(_label(g) for g in granted))
            elif _label(granted) not in ("", "false", "none"):
                out[key].append(_label(granted))
    for key, who in (("perm_all_users_read", _ANON),
                     ("perm_all_users_write", _ANON),
                     ("perm_auth_users_read", _AUTH),
                     ("perm_auth_users_write", _AUTH)):
        value = _label(entry.get(key))
        if value and value not in ("false", "none", "0"):
            out[who].append("write" if key.endswith("write") else "read")
    out[_ANON] = sorted(set(out[_ANON]))
    out[_AUTH] = sorted(set(out[_AUTH]))
    return out


def severity_for(perms: Dict[str, List[str]]) -> str:
    """Anonymous write is the worst thing a bucket can offer."""
    anon, auth = perms.get(_ANON, []), perms.get(_AUTH, [])
    if any(p in ("write", "write_acp", "full_control") for p in anon):
        return "critical"
    if any(p in ("read", "read_acp", "list") for p in anon):
        return "high"
    if any(p in ("write", "write_acp", "full_control") for p in auth):
        return "high"
    if auth:
        return "medium"
    return "info"


def exists(entry: Dict[str, Any]) -> bool:
    """s3scanner reports misses too; only a bucket that EXISTS is a finding."""
    if entry.get("exists") is False:
        return False
    return bool(entry.get("exists")
                or _label(entry.get("bucket_exists")) in ("true", "1")
                or entry.get("name") or entry.get("bucket"))


def keyword_for(target: str) -> str:
    """The brand to permute, from the engagement's host."""
    host = (urlparse(target).hostname or target or "").strip().lower()
    host = host.split(":")[0]
    parts = [p for p in host.split(".") if p and p != "www"]
    if not parts:
        return ""
    # Drop the public suffix; "acme.co.uk" -> "acme".
    if len(parts) >= 3 and len(parts[-2]) <= 3:
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else parts[0]


class S3ScannerWrapper(BaseWrapper):
    name = "s3scanner"
    binary = "s3scanner"
    description = ("Find open object storage across AWS, GCP, DigitalOcean, "
                   "Linode, Scaleway and DreamHost, anonymously.")
    category = "recon"
    timeout_seconds = 12 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        cmd = [self.binary, "-json", "-provider", "all", "-bucket",
               keyword_for(target) or target]
        cmd.extend(options)
        return cmd

    def precondition(self, target: str, options: Sequence[str]) -> str:
        if not keyword_for(target):
            return ("no brand keyword could be derived from this target, and "
                    "bucket discovery is a permutation of one")
        return ""

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int,
              target: str) -> ToolResult:
        findings: List[Finding] = []
        seen = set()
        for entry in iter_json_lines(stdout):
            if not isinstance(entry, dict) or not exists(entry):
                continue
            name = str(entry.get("name") or entry.get("bucket") or "").strip()
            if not name or name in seen:
                continue
            seen.add(name)
            provider = str(entry.get("provider") or "unknown").lower()
            perms = permissions_of(entry)
            severity = severity_for(perms)
            if severity == "info" and not perms[_ANON] and not perms[_AUTH]:
                # It exists and grants nothing we can see. Surface, not a
                # weakness - and worth recording, because the next engagement
                # starts from the inventory this one leaves.
                findings.append(Finding(
                    severity="info",
                    title=f"Object storage bucket exists: {name} ({provider})",
                    description=("The bucket resolves but exposes no "
                                 "anonymous or any-account permission we "
                                 "could observe. Recorded as surface."),
                    target=name,
                    evidence=f"provider: {provider}\nbucket: {name}\n"
                             f"no anonymous or authenticated grant observed",
                    metadata={"tool": "s3scanner", "vuln_class": "recon",
                              "provider": provider, "bucket": name},
                ))
                continue
            who = []
            if perms[_ANON]:
                who.append(f"anyone (unauthenticated): {', '.join(perms[_ANON])}")
            if perms[_AUTH]:
                who.append(f"any cloud account: {', '.join(perms[_AUTH])}")
            writable = any(p in ("write", "write_acp", "full_control")
                           for p in perms[_ANON])
            findings.append(Finding(
                severity=severity,
                title=f"Open object storage: {name} ({provider}) - "
                      f"{'writable' if writable else 'readable'}",
                description=(
                    f"The bucket '{name}' on {provider} grants "
                    f"{'; '.join(who)}. A readable bucket is whatever was put "
                    f"in it - backups, exports, customer uploads - available "
                    f"to anyone who guesses the name, and the name is the "
                    f"brand. A WRITABLE one is worse than a disclosure: "
                    f"whatever consumes the bucket now has an attacker-"
                    f"controlled input, which is how a static asset becomes "
                    f"stored XSS and a build artefact becomes a supply chain."
                    if writable else
                    f"The bucket '{name}' on {provider} grants "
                    f"{'; '.join(who)}. Whatever was put in it - backups, "
                    f"exports, customer uploads - is available to anyone who "
                    f"guesses the name, and the name is the brand."),
                target=name,
                evidence=(f"provider: {provider}\nbucket: {name}\n"
                          + "\n".join(who)),
                metadata={"tool": "s3scanner", "vuln_class": "exposed_bucket",
                          "provider": provider, "bucket": name,
                          "anonymous": perms[_ANON], "authenticated": perms[_AUTH]},
            ))
            if len(findings) >= MAX_FINDINGS:
                break
        return ToolResult(findings=findings)
