"""The certificate, read from one handshake.

A certificate is the cheapest source of scope there is. Its SANs list names the
operator may not have on their scoping document, its issuer says who the
organisation buys from, and its expiry is a finding in its own right often
enough to be worth the two seconds.

The handshake is deliberately permissive - verification off - because a pre-recon
view that refuses to show you an expired or self-signed certificate is refusing
to show you the interesting case. Nothing is trusted as a result: the connection
is used to read the certificate and then dropped, no data is sent, and every
judgement below is computed from the certificate rather than from the fact that
the handshake succeeded.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import logging
import ssl
from typing import Any, Dict, List, Optional

from app.prerecon.budget import CONNECT_TIMEOUT

logger = logging.getLogger("syphax.prerecon.tls")

# Signature algorithms nobody should still be issuing.
WEAK_SIGNATURES = ("md5", "sha1")


def _permissive_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Off on purpose: an expired or self-signed certificate is exactly what we
    # are here to report, and a verifying context would hide it behind an
    # exception. Nothing is sent over this connection.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def fetch(host: str, port: int = 443, *, server_name: str = "") -> Dict[str, Any]:
    """Certificate and protocol details, or {"available": False, "error": ...}."""
    try:
        return await asyncio.wait_for(_fetch(host, port, server_name or host),
                                      timeout=CONNECT_TIMEOUT + 3)
    except asyncio.TimeoutError:
        return {"available": False, "error": "the TLS handshake timed out"}
    except Exception as exc:  # noqa: BLE001 - every socket error means "no TLS here"
        return {"available": False, "error": _readable(exc)}


async def _fetch(host: str, port: int, server_name: str) -> Dict[str, Any]:
    reader, writer = await asyncio.open_connection(
        host, port, ssl=_permissive_context(),
        server_hostname=server_name if not _is_ip(server_name) else None)
    try:
        sslobj = writer.get_extra_info("ssl_object")
        der = sslobj.getpeercert(binary_form=True)
        info = _parse(der)
        info.update({
            "available": True,
            "tls_version": sslobj.version(),
            "cipher": (sslobj.cipher() or [None])[0],
        })
        return info
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 - closing a dead socket is not news
            pass


def _parse(der: bytes) -> Dict[str, Any]:
    from cryptography import x509  # noqa: PLC0415
    from cryptography.hazmat.primitives import hashes  # noqa: PLC0415

    cert = x509.load_der_x509_certificate(der)
    now = dt.datetime.now(dt.timezone.utc)
    not_before = _aware(cert.not_valid_before_utc)
    not_after = _aware(cert.not_valid_after_utc)

    names = _san_names(cert)
    sig = (cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown")

    issues: List[str] = []
    if not_after < now:
        issues.append(f"expired {(now - not_after).days} days ago")
    elif (not_after - now).days <= 30:
        issues.append(f"expires in {(not_after - now).days} days")
    if not_before > now:
        issues.append("not valid yet")
    if any(weak in sig.lower() for weak in WEAK_SIGNATURES):
        issues.append(f"signed with {sig}")
    if _common_name(cert.issuer) == _common_name(cert.subject):
        issues.append("self-signed")
    if len(names) > 50:
        issues.append(f"{len(names)} names on one certificate - a shared edge, not just this host")

    return {
        "subject": _common_name(cert.subject),
        "issuer": _common_name(cert.issuer),
        "issuer_org": _org(cert.issuer),
        "serial": format(cert.serial_number, "x"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": (not_after - now).days,
        "signature_algorithm": sig,
        "key_bits": _key_bits(cert),
        "san": names[:100],
        "san_count": len(names),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "issues": issues,
    }


def _aware(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


def _san_names(cert) -> List[str]:
    from cryptography import x509  # noqa: PLC0415
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except Exception:  # noqa: BLE001 - a certificate with no SAN is legal, just old
        return []
    names = list(ext.value.get_values_for_type(x509.DNSName))
    names += [str(ip) for ip in ext.value.get_values_for_type(x509.IPAddress)]
    return sorted(set(names))


def _common_name(name) -> str:
    from cryptography.x509.oid import NameOID  # noqa: PLC0415
    values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return values[0].value if values else ""


def _org(name) -> str:
    from cryptography.x509.oid import NameOID  # noqa: PLC0415
    values = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    return values[0].value if values else ""


def _key_bits(cert) -> Optional[int]:
    try:
        return cert.public_key().key_size
    except Exception:  # noqa: BLE001 - Ed25519 has no key_size, and that is fine
        return None


def _is_ip(value: str) -> bool:
    import ipaddress  # noqa: PLC0415
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _readable(exc: Exception) -> str:
    text = str(exc) or exc.__class__.__name__
    if isinstance(exc, ConnectionRefusedError):
        return "nothing is listening on that port"
    if isinstance(exc, ssl.SSLError):
        return f"TLS failed: {text}"
    return text
