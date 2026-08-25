# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manage CA certificates for nginx backend trust."""

import hashlib
import logging
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

from errors import CACertificateFileError

logger = logging.getLogger(__name__)

CA_CERTS_DIR = Path("/etc/nginx/certs")
CA_BUNDLE_PATH = CA_CERTS_DIR / "ca-bundle.pem"
SYSTEM_CA_BUNDLE_PATH = Path("/etc/ssl/certs/ca-certificates.crt")


def write_ca_bundle(certificates: list[str]) -> None:
    """Write all CA certificates to the bundle file.

    Replaces any previously written bundle. If the list is empty, removes the
    bundle file so nginx is not configured with an empty trust store.

    Args:
        certificates: PEM-encoded CA certificate strings to trust.

    Raises:
        CACertificateFileError: If a file operation fails.
    """
    try:
        if not certificates:
            CA_BUNDLE_PATH.unlink(missing_ok=True)
            return
        CA_CERTS_DIR.mkdir(parents=True, exist_ok=True)
        CA_BUNDLE_PATH.write_text("\n".join(certificates), encoding="utf-8")
        CA_BUNDLE_PATH.chmod(0o644)
    except (PermissionError, OSError, IOError) as err:
        logger.exception("Failed to write CA bundle")
        raise CACertificateFileError("Unable to write CA bundle") from err


def get_ca_bundle_path() -> Path | None:
    """Return the CA bundle path if it exists and is non-empty, else None.

    Returns:
        The path to the CA bundle, or None if no bundle exists or is empty.
    """
    if not CA_BUNDLE_PATH.exists():
        return None
    if not CA_BUNDLE_PATH.read_text(encoding="utf-8").strip():
        # An empty bundle would cause nginx to reject the config.
        return None
    return CA_BUNDLE_PATH


def load_system_ca_certs() -> list[str]:
    """Return individual PEM certs split from the system CA bundle.

    Returns:
        A list of PEM-encoded certificate strings, or an empty list if the
        system CA bundle does not exist.
    """
    if not SYSTEM_CA_BUNDLE_PATH.exists():
        return []
    content = SYSTEM_CA_BUNDLE_PATH.read_text(encoding="utf-8")
    certs: list[str] = []
    current: list[str] = []
    for line in content.splitlines(keepends=True):
        current.append(line)
        if "-----END CERTIFICATE-----" in line:
            certs.append("".join(current).strip())
            current = []
    return certs


def _cert_sha256_fingerprint(cert_pem: str) -> str:
    """Return the SHA-256 fingerprint of a PEM-encoded certificate.

    Args:
        cert_pem: The PEM-encoded certificate to fingerprint.

    Returns:
        The certificate fingerprint as colon-separated uppercase hex.
    """
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    der = cert.public_bytes(serialization.Encoding.DER)
    return ":".join(f"{byte:02X}" for byte in hashlib.sha256(der).digest())


def find_cert_by_fingerprint(fingerprint: str, pem_certs: list[str]) -> str | None:
    """Return the first PEM certificate whose fingerprint matches.

    Args:
        fingerprint: The target SHA-256 fingerprint.
        pem_certs: The PEM-encoded certificates to search.

    Returns:
        The matching PEM certificate, or None if no match is found.
    """
    normalised = fingerprint.strip().upper()
    for pem in pem_certs:
        pem = pem.strip()
        if not pem:
            continue
        try:
            cert_fingerprint = _cert_sha256_fingerprint(pem)
        except (ValueError, UnsupportedAlgorithm):
            continue
        if cert_fingerprint == normalised:
            return pem
    return None


BACKEND_CA_BUNDLE_PATH = CA_CERTS_DIR / "backend-ca-bundle.pem"


def write_backend_ca_bundle(certs: list[str]) -> Path | None:
    """Write all matched backend CA certificates to a single bundle file.

    Replaces any previously written bundle. If the list is empty, removes the
    bundle file so nginx is not configured with an empty trust store. This
    mirrors the holistic approach used by :func:`write_ca_bundle` for frontend
    client CA certificates.

    Args:
        certs: PEM-encoded CA certificate strings to trust for backend connections.

    Returns:
        The path to the written bundle, or None if the list was empty.

    Raises:
        CACertificateFileError: If a file operation fails.
    """
    try:
        if not certs:
            BACKEND_CA_BUNDLE_PATH.unlink(missing_ok=True)
            return None
        CA_CERTS_DIR.mkdir(parents=True, exist_ok=True)
        BACKEND_CA_BUNDLE_PATH.write_text("\n".join(certs), encoding="utf-8")
        BACKEND_CA_BUNDLE_PATH.chmod(0o644)
        return BACKEND_CA_BUNDLE_PATH
    except (PermissionError, OSError, IOError) as err:
        logger.exception("Failed to write backend CA bundle")
        raise CACertificateFileError("Unable to write backend CA bundle") from err
