"""Leaked cloud credentials -> what they can actually do (IAM privilege probe).

trufflehog and jsluice already FIND secrets. This closes the loop the user
asked for: when an AWS key pair leaks, prove its blast radius - is it live, who
is it, and is it over-permissive?

Active and gated. It authenticates to AWS with the discovered key and makes a
bounded set of READ-ONLY calls (STS GetCallerIdentity, then a few list/get
probes). It never creates, changes or deletes anything. Because it uses a real
credential against a real cloud account it is gated behind the engagement's
allow_active_exploit, exactly like every other active step, and runs only when
the operator passed the exploitation checkpoint.

boto3 is imported lazily so the base image stays slim and a missing SDK
degrades to "skipped" instead of an import error.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Dict, List, Optional, Tuple

from app.analysis._store import save_analysis_job
from app.engagements import EngagementRepository
from app.scans.models import Finding
from app.validation import ValidatedFindingRepository

logger = logging.getLogger("syphax.intel.cloud_creds")

# AWS access key id, and a secret access key appearing near it.
_AKID = re.compile(r"\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b")
_SECRET = re.compile(r"\b([A-Za-z0-9/+=]{40})\b")

# Read-only probes, each (label, lambda session -> truthy on success). Kept
# small and strictly non-mutating. A success means the key holds that read
# permission; the breadth of successes is the privilege summary.
_READ_PROBES = [
    ("iam:GetUser", lambda s: s.client("iam").get_user()),
    ("iam:ListAttachedUserPolicies",
     lambda s: s.client("iam").list_attached_user_policies(
         UserName=s.client("sts").get_caller_identity()["Arn"].split("/")[-1])),
    ("s3:ListAllMyBuckets", lambda s: s.client("s3").list_buckets()),
    ("ec2:DescribeInstances",
     lambda s: s.client("ec2", region_name="us-east-1").describe_instances(MaxResults=5)),
    ("secretsmanager:ListSecrets",
     lambda s: s.client("secretsmanager", region_name="us-east-1").list_secrets(MaxResults=1)),
]


async def probe_leaked_cloud_creds(engagement_id: str) -> Dict[str, int]:
    """Find leaked AWS key pairs in this engagement's findings and probe them.

    Returns a small count dict. Caller gates on allow_active_exploit.
    """
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    vf_repo = ValidatedFindingRepository()
    vfs = await vf_repo.list(engagement_id)
    pairs = _extract_aws_pairs(vfs)
    if not pairs:
        # This returned {"skipped": 1} without a word. "No cloud credential
        # was found in this engagement's findings" is worth one line: the
        # alternative is the operator assuming the probe ran and found nothing
        # live, which is a different and much more alarming statement.
        await _say(engagement_id,
                   "Cloud-credential probe: no AWS key pair appears in this "
                   "engagement's findings, so nothing was probed.")
        return {"skipped": 1}

    findings: List[Finding] = []
    confirmed = 0
    for akid, secret, origin_id in pairs:
        try:
            result = await asyncio.to_thread(_probe_aws, akid, secret)
        except Exception:  # noqa: BLE001 - never fail the run on a probe
            logger.exception("[%s] AWS cred probe crashed", engagement_id)
            continue
        if result is None:
            await _say(engagement_id,
                       f"Cloud-credential probe: {akid[:8]}... is not live "
                       f"(AWS refused it), so the leak is not exploitable.")
            continue
        findings.append(_finding_for(akid, result))

        # Confirm the finding the key came OUT of, here and now.
        #
        # This phase runs after validate_engagement, so the job finding written
        # above is never validated during this run: it reaches neither the
        # Findings page (which reads validated_findings) nor the report. And
        # "cloud_creds" was not in validator._ANALYSIS_TOOLS, so even the next
        # validation pass ignored its precomputed verdict and fell back to a
        # scanner-match heuristic. A live, probe-verified AWS key - the single
        # most serious thing this tool can find - surfaced nowhere at all.
        if not origin_id:
            continue
        try:
            await vf_repo.update_verdict(
                origin_id, status="confirmed", confidence=0.98,
                method="cloud-credential probe: the key authenticated to AWS")
            await vf_repo.set_metadata(origin_id, {
                "proven": True,
                "exploitation": {
                    "route": "cloud-credential probe",
                    "account": result.get("account"),
                    "arn": result.get("arn"),
                    "permissions": sorted(result.get("allowed") or []),
                    "note": "the leaked key authenticated to AWS and these "
                            "read-only probes succeeded",
                },
            })
            confirmed += 1
            await _say(engagement_id,
                       f"Cloud-credential probe: {akid[:8]}... is LIVE in account "
                       f"{result.get('account')} - the leak it came from is now "
                       f"confirmed, not likely.")
        except Exception:  # noqa: BLE001 - never fail the run on a verdict write
            logger.exception("[%s] could not confirm finding %s from the cloud "
                             "probe", engagement_id, origin_id)

    if findings:
        await save_analysis_job(engagement_id, "cloud_creds", findings,
                                target=eng.target_host or eng.target_url)
    return {"keys_probed": len(pairs), "live": len(findings),
            "confirmed": confirmed}


async def _say(engagement_id: str, message: str) -> None:
    """One line in the live view. Never raises."""
    try:
        from app import events
        await events.emit(engagement_id, events.THOUGHT, message,
                          level=events.LEVEL_INFO)
    except Exception:  # noqa: BLE001 - reporting never fails a probe
        logger.debug("could not emit: %s", message)


def _extract_aws_pairs(vfs) -> List[Tuple[str, str, str]]:
    """Pull (access_key_id, secret_access_key, origin_finding_id) out of findings.

    The finding id rides along so a live key can confirm the leak it came from.
    Without it the probe's proof had nowhere to land: it wrote a brand-new job
    finding that this run never validates.
    """
    pairs: List[Tuple[str, str, str]] = []
    seen = set()
    for f in vfs:
        blob = " ".join(str(x) for x in (
            getattr(f, "evidence", "") or "",
            getattr(f, "poc", "") or "",
            " ".join(f"{k}={v}" for k, v in (getattr(f, "metadata", None) or {}).items()),
        ))
        akids = _AKID.findall(blob)
        if not akids:
            continue
        secrets = [s for s in _SECRET.findall(blob) if not s.startswith(("AKIA", "ASIA"))]
        for akid in akids:
            # Pair each key id with the nearest plausible secret (best-effort;
            # most leaks place them together). If none, skip - a probe needs both.
            if not secrets:
                continue
            key = (akid, secrets[0])
            if key not in seen:
                seen.add(key)
                pairs.append((akid, secrets[0], str(getattr(f, "id", "") or "")))
    return pairs


def _probe_aws(akid: str, secret: str) -> Optional[Dict]:
    """STS GetCallerIdentity + read-only probes. None if the key is not live."""
    try:
        import boto3  # lazy: optional dependency
        from botocore.config import Config
    except Exception:  # noqa: BLE001
        logger.warning("boto3 not installed - skipping AWS credential probe")
        return None

    cfg = Config(retries={"max_attempts": 1}, connect_timeout=8, read_timeout=12)
    session = boto3.session.Session(
        aws_access_key_id=akid, aws_secret_access_key=secret,
        region_name="us-east-1")
    try:
        ident = session.client("sts", config=cfg).get_caller_identity()
    except Exception:  # noqa: BLE001 - invalid/expired/revoked key
        return None

    allowed: List[str] = []
    for label, call in _READ_PROBES:
        try:
            call(session)
            allowed.append(label)
        except Exception:  # noqa: BLE001 - denied or not applicable
            continue
    return {
        "account": ident.get("Account"),
        "arn": ident.get("Arn"),
        "user_id": ident.get("UserId"),
        "allowed": allowed,
    }


def _finding_for(akid: str, result: Dict) -> Finding:
    allowed = result.get("allowed") or []
    # Over-permissive if it can enumerate IAM/EC2/secrets, not just its own identity.
    broad = any(p.split(":")[0] in ("iam", "ec2", "secretsmanager") for p in allowed)
    sev = "critical" if broad else "high"
    perms = ", ".join(allowed) if allowed else "identity only (STS)"
    return Finding(
        severity=sev,
        title=f"Live AWS key {akid[:8]}… - {'over-permissive' if broad else 'valid'}",
        description=(f"A leaked AWS access key is live. Identity {result.get('arn')} "
                     f"in account {result.get('account')}. Read-only probes that "
                     f"succeeded: {perms}. Rotate/disable this key immediately and "
                     f"audit its CloudTrail history."),
        target=str(result.get("arn") or result.get("account") or akid),
        evidence=f"account={result.get('account')} arn={result.get('arn')} perms=[{perms}]",
        metadata={
            "vuln_class": "privilege_escalation" if broad else "secret_exposure",
            "cloud_provider": "aws", "account": result.get("account"),
            "arn": result.get("arn"), "allowed": allowed, "tool": "cloud_creds",
            "proven": True,
        },
    )
