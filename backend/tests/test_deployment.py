"""How this thing gets onto a host, asserted against the files that do it.

These read like configuration tests because that is where the properties live.
A secret that ships as a default, a port that publishes on every interface, a
duplicated key in .env.example - none of these break anything visibly. The
install works, the UI comes up, and the problem is only ever discovered by
someone who was looking for it.
"""
from __future__ import annotations

import collections
import pathlib
import re

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "docker-compose.yml"
ENV_EXAMPLE = ROOT / ".env.example"
INSTALL = ROOT / "install.sh"


@pytest.fixture(scope="module")
def compose():
    return yaml.safe_load(COMPOSE.read_text())


@pytest.fixture(scope="module")
def env_example():
    return ENV_EXAMPLE.read_text()


@pytest.fixture(scope="module")
def install():
    return INSTALL.read_text()


def env_pairs(text):
    return [line.split("=", 1) for line in text.splitlines()
            if line and not line.startswith("#") and "=" in line]


# ---- .env.example -----------------------------------------------------------

def test_no_key_is_declared_twice():
    """A second declaration silently wins, and the reader has no way to tell
    which one is live. SYPHAX_SECRET_KEY was declared in two sections."""
    keys = [k for k, _ in env_pairs(ENV_EXAMPLE.read_text())]
    dupes = sorted(k for k, n in collections.Counter(keys).items() if n > 1)
    assert dupes == [], f"declared more than once in .env.example: {dupes}"


def test_every_variable_compose_interpolates_is_documented(compose, env_example):
    """A variable compose reads but the example never mentions is one the
    operator finds out about from a container that will not start."""
    raw = COMPOSE.read_text()
    referenced = set(re.findall(r"\$\{([A-Z_][A-Z0-9_]*)(?::-[^}]*)?\}", raw))
    documented = {k for k, _ in env_pairs(env_example)}
    # DATABASE_URL and friends are composed inside the compose file itself.
    internal = {"DATABASE_URL", "REDIS_URL", "SANDBOX_ALLOWED_HOSTS",
                "SANDBOX_MAX_TIMEOUT"}
    missing = referenced - documented - internal
    assert not missing, f"used by docker-compose.yml, absent from .env.example: {sorted(missing)}"


def test_no_secret_ships_with_a_usable_default(env_example):
    """Empty is fine - it means "you or the installer must fill this in". A
    plausible-looking value is not: it gets left alone."""
    for key, value in env_pairs(env_example):
        if any(w in key for w in ("SECRET", "API_KEY", "TOKEN", "PASSWORD")):
            if key == "POSTGRES_PASSWORD":
                continue  # covered below: the installer replaces it
            assert value.strip() == "", f"{key} ships with a value"


# ---- exposure ---------------------------------------------------------------

def test_the_ui_and_api_bind_to_loopback_unless_told_otherwise(compose):
    ports = compose["services"]["backend"]["ports"]
    api = [p for p in ports if p.endswith(":8000")]
    assert api == ["${BIND_ADDRESS:-127.0.0.1}:8000:8000"]
    assert compose["services"]["frontend"]["ports"] == \
        ["${BIND_ADDRESS:-127.0.0.1}:3000:80"]


def test_the_mitmproxy_port_has_its_own_variable(compose):
    """The regression this prevents is one variable for both.

    An operator setting BIND_ADDRESS=0.0.0.0 wants the UI reachable. If 8080
    followed, they would also have published an unauthenticated
    HTTPS-intercepting proxy with a CA their devices trust - an open relay,
    acquired as a side effect of wanting to log in from a laptop.
    """
    ports = compose["services"]["backend"]["ports"]
    proxy = [p for p in ports if p.endswith(":8080")]
    assert proxy == ["${PROXY_BIND_ADDRESS:-127.0.0.1}:8080:8080"]
    assert "PROXY_BIND_ADDRESS" in ENV_EXAMPLE.read_text()


def test_postgres_is_not_published_to_the_host(compose):
    assert "ports" not in compose["services"]["postgres"]
    assert "ports" not in compose["services"]["redis"]


# ---- the installer ----------------------------------------------------------

def test_the_installer_generates_the_secrets_it_needs(install):
    """Not "reminds you to set". A default that requires a human step is a
    default that survives into production."""
    assert "set_env POSTGRES_PASSWORD" in install
    assert "set_env SYPHAX_SECRET_KEY" in install
    assert "random_hex" in install


def test_the_installer_works_without_openssl(install):
    """A minimal VM image often has no openssl. /dev/urandom is always there."""
    assert "/dev/urandom" in install


def test_the_installer_refuses_to_expose_the_ui_silently(install):
    assert "--bind" in install
    assert "There is no TLS in this stack" in install
    # And it stops for confirmation unless explicitly told not to.
    assert "ASSUME_YES" in install


def test_the_installer_can_seed_an_account_but_never_resets_one(install):
    assert "--admin-user" in install
    assert "SYPHAX_ADMIN_USER" in install
    # The guarantee is enforced in app/auth/storage.bootstrap_from_env, which
    # returns before creating anything if any account already exists. Asserted
    # against the source, not the docstring: a comment cannot protect a
    # password.
    import inspect
    from app.auth import storage
    body = inspect.getsource(storage.bootstrap_from_env)
    create_at = body.index("create_user(")
    guard_at = body.index("if await has_users():")
    assert guard_at < create_at, \
        "the existing-account check must run before the account is created"


def test_the_installer_still_names_no_provider_key_as_the_setup_step(install):
    """It used to end with "edit .env and set OPENROUTER_API_KEY". Keys are
    entered in the UI now, and that instruction sent people to the wrong file."""
    assert "OPENROUTER_API_KEY" not in install


def test_the_env_file_is_not_world_readable_after_install(install):
    assert "chmod 600 .env" in install


def test_no_bare_test_and_command_on_a_final_line(install):
    """`[ -n "$X" ] && { ...; }` as a statement exits the script under `set -e`
    when the test is false. It did, silently, whenever --bind was omitted."""
    assert "set -euo pipefail" in install
    for i, line in enumerate(install.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("[") and "] && {" in stripped:
            pytest.fail(f"install.sh:{i} exits the script when the test is false")
