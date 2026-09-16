"""Password hashing and the rules a password has to clear.

No new dependency. PBKDF2-HMAC-SHA256 from the standard library is not the
strongest KDF available - Argon2id is - but it is the strongest one that is
already installed everywhere this runs, including the CI image that deliberately
does not install the full production stack. A dependency that has to be added to
three requirements files to hash one password is a dependency that eventually
gets skipped on some install, and a skipped KDF is worse than a slightly weaker
one.

Iteration count follows the OWASP 2023 recommendation for PBKDF2-HMAC-SHA256.
The stored format carries its own parameters, so raising it later re-hashes
on next login instead of invalidating every account.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
from typing import List, Tuple

ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 600_000
SALT_BYTES = 16

# Length beats composition rules: a 14-character passphrase is stronger than
# "P@ssw0rd!" and an operator will actually remember it. We ask for length and
# refuse the handful of things that are never a real password.
MIN_LENGTH = 12
MAX_LENGTH = 1024      # bounds the KDF's input; not a security control

# Not a dictionary - a dictionary belongs in a service with a rate limiter, and
# we have one of those. This is the short list of strings people type when they
# are trying to get past a setup form and mean to change it later, which they
# never do.
OBVIOUS = frozenset({
    "password", "password1", "passw0rd", "motdepasse", "changeme", "letmein",
    "admin", "administrator", "root", "toor", "syphax", "syphax123",
    "12345678", "123456789", "1234567890", "qwertyuiop", "azertyuiop",
    "iloveyou", "welcome", "secret", "pentest", "hackme",
})

_b64 = base64.b64encode
_unb64 = base64.b64decode


def _derive(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


def hash_password(password: str, *, iterations: int = ITERATIONS,
                  salt: bytes | None = None) -> str:
    """Return `pbkdf2_sha256$<iterations>$<b64 salt>$<b64 digest>`."""
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    salt = salt if salt is not None else os.urandom(SALT_BYTES)
    digest = _derive(password, salt, iterations)
    return "$".join([ALGORITHM, str(iterations),
                     _b64(salt).decode(), _b64(digest).decode()])


def parse_hash(stored: str) -> Tuple[str, int, bytes, bytes]:
    """Split a stored hash. Raises ValueError on anything malformed."""
    parts = (stored or "").split("$")
    if len(parts) != 4:
        raise ValueError("malformed password hash")
    algo, iters, salt_b64, digest_b64 = parts
    if algo != ALGORITHM:
        raise ValueError(f"unsupported algorithm: {algo}")
    return algo, int(iters), _unb64(salt_b64), _unb64(digest_b64)


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check. A malformed or empty stored hash is a failure, not
    an exception: a corrupted row must lock the account, never open it."""
    if not password or not stored:
        return False
    try:
        _algo, iterations, salt, expected = parse_hash(stored)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(_derive(password, salt, iterations), expected)


def needs_rehash(stored: str, *, iterations: int = ITERATIONS) -> bool:
    """True when the stored hash used weaker parameters than we use now."""
    try:
        _algo, stored_iterations, _salt, _digest = parse_hash(stored)
    except (ValueError, TypeError):
        return True
    return stored_iterations < iterations


# ---- what counts as an acceptable password ---------------------------------

def normalise_username(raw: str) -> str:
    """Usernames are compared lowercased and trimmed, so `Admin` and `admin `
    cannot become two accounts that look identical in the UI."""
    return (raw or "").strip().lower()


_USERNAME_OK = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")


def username_problems(username: str) -> List[str]:
    u = normalise_username(username)
    if not u:
        return ["username is required"]
    if not _USERNAME_OK.match(u):
        return ["username must be 2-32 characters: letters, digits, dot, dash "
                "or underscore, starting with a letter or digit"]
    return []


def password_problems(password: str, *, username: str = "") -> List[str]:
    """Every reason this password is refused, so the UI can show them at once
    instead of one per round-trip."""
    problems: List[str] = []
    pw = password or ""
    if len(pw) < MIN_LENGTH:
        problems.append(f"password must be at least {MIN_LENGTH} characters")
    if len(pw) > MAX_LENGTH:
        problems.append(f"password must be at most {MAX_LENGTH} characters")
    if pw.strip() != pw:
        problems.append("password must not start or end with whitespace")
    low = pw.lower()
    if low in OBVIOUS:
        problems.append("that password is one of the first an attacker tries")
    u = normalise_username(username)
    if u and u in low:
        problems.append("password must not contain the username")
    if pw and len(set(pw)) < 5:
        problems.append("password repeats too few distinct characters")
    return problems
