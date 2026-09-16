"""Static inspection of a third-party PoC, before anyone considers running it.

The threat model here points the wrong way round from what people expect. A PoC
fetched from GitHub is not primarily a risk to the target - it is a risk to the
operator. Repositories advertising a PoC for a fresh CVE, containing a stealer
that reads ~/.ssh and ~/.aws and posts them somewhere, are a recurring and
well-documented attack on security researchers. The person running it has
credentials for client environments; that is the whole point of hitting them.

So this reads the code and answers one question: does it do anything other than
attack the target it claims to attack?

It is a reviewer's aid, not a verdict. Static analysis of hostile code is
defeatable by construction - anything found here is real, but finding nothing
proves nothing, and the module says so rather than implying a clean bill of
health. The operator still reads the code; this points at the lines worth
reading first.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

SEV_CRITICAL = "critical"
SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_INFO = "info"

_SEV_RANK = {SEV_CRITICAL: 0, SEV_HIGH: 1, SEV_MEDIUM: 2, SEV_INFO: 3}


@dataclass
class Signal:
    """One thing worth a human's attention, anchored to a line."""
    category: str
    severity: str
    line_no: int
    line: str
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {"category": self.category, "severity": self.severity,
                "line_no": self.line_no, "line": self.line[:200],
                "detail": self.detail}


@dataclass
class Report:
    signals: List[Signal] = field(default_factory=list)
    external_hosts: List[str] = field(default_factory=list)
    verdict: str = "review"          # review | suspicious | hostile
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"verdict": self.verdict, "summary": self.summary,
                "external_hosts": self.external_hosts,
                "signals": [s.to_dict() for s in self.signals]}


# Each rule is (category, severity, compiled pattern, detail).
# Kept deliberately readable: a reviewer should be able to audit the rules
# themselves, and a rule nobody understands is a rule nobody trusts.
_RULES = [
    # --- Credential harvesting: the researcher's own secrets ---
    ("credential_access", SEV_CRITICAL,
     re.compile(r"\.ssh/|id_rsa|id_ed25519|authorized_keys", re.I),
     "reads SSH private keys"),
    ("credential_access", SEV_CRITICAL,
     re.compile(r"\.aws/credentials|\.aws/config|AWS_SECRET_ACCESS_KEY", re.I),
     "reads AWS credentials"),
    ("credential_access", SEV_CRITICAL,
     re.compile(r"\.docker/config\.json|\.kube/config|\.npmrc|\.pypirc|\.netrc", re.I),
     "reads stored service credentials"),
    ("credential_access", SEV_HIGH,
     re.compile(r"os\.environ\b(?!\.get\(['\"](?:HOME|PATH|USER|PWD|LANG)\b)|process\.env\b",
                re.I),
     "reads the environment, which holds this tool's API keys"),
    ("credential_access", SEV_HIGH,
     re.compile(r"Login Data|cookies\.sqlite|key4\.db|logins\.json|Local State", re.I),
     "reads browser credential stores"),
    ("credential_access", SEV_HIGH,
     re.compile(r"security\s+find-generic-password|keychain|secret-tool\s+lookup", re.I),
     "reads the OS keychain"),

    # --- Reverse shells and remote control ---
    ("reverse_shell", SEV_CRITICAL,
     re.compile(r"(?:bash|sh)\s+-i\s*>&|/dev/tcp/|nc\s+(?:-[a-z]*e|--exec)", re.I),
     "opens a reverse shell"),
    ("reverse_shell", SEV_CRITICAL,
     re.compile(r"pty\.spawn|subprocess\.(?:call|Popen)\s*\(\s*\[?\s*['\"]/bin/(?:ba)?sh",
                re.I),
     "spawns an interactive shell"),

    # --- Obfuscation: hiding what the code does ---
    ("obfuscation", SEV_CRITICAL,
     re.compile(r"(?:eval|exec)\s*\(\s*(?:base64|codecs|zlib|marshal|pickle)", re.I),
     "executes decoded data - the real payload is hidden"),
    ("obfuscation", SEV_HIGH,
     re.compile(r"(?:eval|exec|Function)\s*\(\s*(?:atob|unescape|fromCharCode)", re.I),
     "executes decoded data"),
    ("obfuscation", SEV_MEDIUM,
     re.compile(r"[A-Za-z0-9+/]{200,}={0,2}"),
     "long encoded blob"),

    # --- Persistence and install-time execution ---
    ("persistence", SEV_CRITICAL,
     re.compile(r"crontab|systemd/system|LaunchAgents|\.bashrc|\.zshrc|authorized_keys",
                re.I),
     "writes to a persistence location"),
    ("install_hook", SEV_CRITICAL,
     re.compile(r"preinstall|postinstall|cmdclass\s*=|setup_requires|__import__\s*\(",
                re.I),
     "runs code at install time, before you ever invoke it"),

    # --- Destructive ---
    ("destructive", SEV_CRITICAL,
     re.compile(r"rm\s+-rf\s+[~/]|shutil\.rmtree\s*\(\s*['\"]?[~/]|mkfs|dd\s+if=/dev/(?:zero|urandom)",
                re.I),
     "deletes or overwrites data outside the working directory"),

    # --- Privilege ---
    ("privilege", SEV_HIGH,
     re.compile(r"\bsudo\b|chmod\s+[+]?[0-7]*s|setuid", re.I),
     "escalates privilege"),

    # --- Exfiltration primitives ---
    ("exfiltration", SEV_HIGH,
     re.compile(r"requests\.(?:post|put)\s*\(|urlopen\s*\(|curl\s+-[a-zA-Z]*[dF]|"
                r"fetch\s*\(\s*['\"]https?://", re.I),
     "sends data outward"),
    ("exfiltration", SEV_HIGH,
     re.compile(r"webhook\.site|requestbin|pipedream|ngrok\.io|burpcollaborator|"
                r"interact\.sh|oastify", re.I),
     "contacts a known collector service"),
    ("exfiltration", SEV_CRITICAL,
     re.compile(r"api\.telegram\.org|discord(?:app)?\.com/api/webhooks|pastebin\.com/api",
                re.I),
     "posts to an attacker-controlled channel"),
]

_URL_RE = re.compile(r"https?://([A-Za-z0-9._-]+(?::\d+)?)")

# Hosts a PoC legitimately talks to that are not exfiltration.
_BENIGN_HOSTS = {
    "github.com", "raw.githubusercontent.com", "gist.github.com",
    "pypi.org", "files.pythonhosted.org", "registry.npmjs.org",
    "nvd.nist.gov", "cve.mitre.org", "exploit-db.com", "www.exploit-db.com",
    "localhost", "127.0.0.1", "0.0.0.0", "example.com", "www.example.com",
}


def _host_in_scope(host: str, scope_hosts: Sequence[str]) -> bool:
    h = host.split(":", 1)[0].lower()
    for s in scope_hosts or []:
        s = (s or "").strip().lower().lstrip("*.")
        if not s:
            continue
        if h == s or h.endswith("." + s):
            return True
    return False


def external_hosts(code: str, scope_hosts: Sequence[str]) -> List[str]:
    """Hosts the code contacts that are neither in scope nor obviously benign.

    This is the single most useful signal: a genuine PoC talks to the target.
    Anything else it reaches out to deserves an explanation.
    """
    found: List[str] = []
    for raw in _URL_RE.findall(code or ""):
        host = raw.split(":", 1)[0].lower()
        if host in _BENIGN_HOSTS or _host_in_scope(host, scope_hosts):
            continue
        if host not in found:
            found.append(host)
    return found


def inspect_code(code: str, *, scope_hosts: Optional[Sequence[str]] = None,
                 filename: str = "") -> Report:
    """Read a PoC and report what deserves a human's eye, with line numbers."""
    report = Report()
    if not (code or "").strip():
        report.summary = "empty file"
        return report

    lines = code.splitlines()
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        for category, severity, pattern, detail in _RULES:
            if pattern.search(line):
                report.signals.append(
                    Signal(category=category, severity=severity, line_no=idx,
                           line=stripped, detail=detail))

    report.external_hosts = external_hosts(code, scope_hosts or [])
    for host in report.external_hosts:
        report.signals.append(Signal(
            category="external_host", severity=SEV_HIGH, line_no=0, line=host,
            detail=f"contacts {host}, which is neither in scope nor a known package source"))

    report.signals.sort(key=lambda s: (_SEV_RANK.get(s.severity, 9), s.line_no))

    worst = report.signals[0].severity if report.signals else SEV_INFO
    if worst == SEV_CRITICAL:
        report.verdict = "hostile"
    elif worst in (SEV_HIGH, SEV_MEDIUM):
        report.verdict = "suspicious"
    else:
        report.verdict = "review"

    report.summary = _summarize(report, filename)
    return report


def _summarize(report: Report, filename: str) -> str:
    name = filename or "this file"
    if not report.signals:
        # Deliberately not "clean": static analysis of hostile code is
        # defeatable, and implying safety here would be the dangerous part.
        return (f"No known-bad pattern matched in {name}. That is not a clean "
                f"bill of health - read it before running it.")
    by_cat: Dict[str, int] = {}
    for s in report.signals:
        by_cat[s.category] = by_cat.get(s.category, 0) + 1
    parts = ", ".join(f"{k} x{v}" for k, v in sorted(by_cat.items()))
    return f"{len(report.signals)} signal(s) in {name}: {parts}"
