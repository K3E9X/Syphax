"""nord-stream: extract secrets from CI/CD by deploying pipelines.

This tool is different in kind from every other wrapper here, and the
difference is the whole reason it has a gate. A scanner READS a target. This
one WRITES to the client's own CI/CD: it pushes a branch, deploys a workflow
that dumps the configured secrets, and can temporarily lift branch
protections to do it. That is action against infrastructure the engagement's
URL does not even name, with credentials (a GitHub/GitLab/Azure DevOps PAT)
the operator supplies, under an authorisation that has to cover it
specifically.

So it does not run from the autonomous planner, and it does not run on an
engagement that merely allows active exploitation. `requires_capability`
makes app/workers.py refuse the job unless the engagement declares BOTH the
destructive and persistence capabilities - destructive because it changes the
repository, persistence because a deployed pipeline is a thing left running
until cleanup - and `precondition` refuses it again if the operator has not
supplied the platform and token it needs. Two independent gates, because the
cost of getting this one wrong is a change to someone else's production CI.

The operator drives it by passing the platform, the target and the token in
`options`; nothing is derived from the engagement target, because the target
is a web app and this acts on a source-control org.
"""
from __future__ import annotations

from typing import List, Sequence

from app.exploit.capabilities import CAP_DESTRUCTIVE, CAP_PERSISTENCE
from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult

_PLATFORMS = ("github", "gitlab", "azure", "devops")
_TOKEN_FLAGS = ("--token", "--pat", "-t", "--gitlab-session", "--jwt")


class NordStreamWrapper(BaseWrapper):
    name = "nord_stream"
    # Invoked as `python3 /opt/nord-stream/nord-stream.py`; the resolver below
    # turns the bare name into that, so the registry still keys it by one word.
    binary = "nord_stream"
    description = ("Extract CI/CD secrets by deploying pipelines. Changes the "
                   "client's own source control; gated on declared capabilities.")
    category = "exploit"
    timeout_seconds = 15 * 60

    # The engagement must declare BOTH. This is the mechanism that makes "the
    # operator decides, with written authorisation" a property of the system
    # rather than a note in a wrapper.
    requires_capability = (CAP_DESTRUCTIVE, CAP_PERSISTENCE)

    def _resolve_binary(self) -> List[str]:
        import os
        for path in ("/opt/nord-stream/nord-stream.py",
                     "/opt/nord-stream/nordstream.py"):
            if os.path.isfile(path):
                return ["python3", path]
        return ["nord-stream"]

    def is_available(self) -> bool:
        import os
        return any(os.path.isfile(p) for p in
                   ("/opt/nord-stream/nord-stream.py",
                    "/opt/nord-stream/nordstream.py"))

    def precondition(self, target: str, options: Sequence[str]) -> str:
        opts = [str(o).lower() for o in options]
        if not any(p in opts or f"--{p}" in opts for p in _PLATFORMS):
            return ("nord-stream needs a platform (github / gitlab / azure) in "
                    "its options; it acts on a source-control org, not on the "
                    "engagement's web target, so nothing can be derived for it")
        if not any(flag in opts for flag in _TOKEN_FLAGS):
            return ("nord-stream needs an operator-supplied access token: it "
                    "authenticates to the client's CI/CD as the operator, and "
                    "there is nothing to capture a token from here")
        return ""

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        # The operator's options ARE the command. We prepend the interpreter
        # and pass everything through, rather than constructing a line: the
        # tool's own flags change between platforms and we do not second-guess
        # an operator who has read its help and holds the authorisation.
        return self._resolve_binary() + list(options)

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int,
              target: str) -> ToolResult:
        text = (stdout or b"").decode("utf-8", errors="replace")
        lower = text.lower()
        findings: List[Finding] = []
        # A secret recovered from a pipeline is the finding, and the evidence
        # is redacted: the point is to prove the secret was reachable, not to
        # reprint it into a report.
        from app.exploit.redaction import redact_secrets
        if any(marker in lower for marker in
               ("secret", "token", "password", "credential", "recovered")):
            findings.append(Finding(
                severity="high",
                title=f"CI/CD secrets reachable via pipeline deployment: {target}",
                description=(
                    "nord-stream deployed a pipeline into the configured CI/CD "
                    "project and it returned secret material. A secret that a "
                    "pushed pipeline can read is a secret anyone who can push - "
                    "or who compromises a contributor - can exfiltrate, and it "
                    "usually unlocks far more than the repository. Rotate every "
                    "value it returned and move them to a scoped, audited "
                    "secret store with deployment-time injection."),
                target=target,
                evidence=redact_secrets(text[:4000]),
                metadata={"tool": "nord_stream", "vuln_class": "secret_exposure",
                          "status": "confirmed", "confidence": 0.85,
                          "exit_code": exit_code},
            ))
        return ToolResult(findings=findings)
