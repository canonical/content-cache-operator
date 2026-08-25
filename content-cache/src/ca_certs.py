# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manage CA certificates for nginx backend trust."""

import hashlib
import logging
from pathlib import Path

from cryptography import x509
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

    Reads SYSTEM_CA_BUNDLE_PATH and splits it into individual PEM certificate strings.

    Returns:
        A list of PEM-encoded certificate strings. Empty list if the bundle
        does not exist or is empty.
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

    The fingerprint is computed over the DER-encoded form of the certificate,
    formatted as colon-separated uppercase hex.

    Args:
        cert_pem: A PEM-encoded certificate string.

    Returns:
        The SHA-256 fingerprint as colon-separated uppercase hex.
    """
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    der = cert.public_bytes(serialization.Encoding.DER)
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, 64, 2))


def find_cert_by_fingerprint(fingerprint: str, pem_certs: list[str]) -> str | None:
    """Return the PEM string of the first cert whose SHA-256 DER fingerprint matches.

    Comparison is case-insensitive. Invalid PEM entries are silently skipped.

    Args:
        fingerprint: The target SHA-256 fingerprint, colon-separated hex (any case).
        pem_certs: A list of PEM-encoded certificate strings to search.

    Returns:
        The matching PEM certificate string, or None if no match is found.
    """
    normalised = fingerprint.strip().upper()
    for pem in pem_certs:
        pem = pem.strip()
        if not pem:
            continue
        try:
            fp = _cert_sha256_fingerprint(pem)
            if fp == normalised:
                return pem
        except Exception:  # noqa: BLE001
            continue
    return None


def write_backend_ca_cert(identifier: str, cert_pem: str) -> Path:
    """Write a per-relation backend CA certificate to disk.

    The file is written to CA_CERTS_DIR/backend-<identifier>-ca.pem. Any
    previous file for this identifier is overwritten.

    Args:
        identifier: A unique string identifying the relation (typically the port number).
        cert_pem: The PEM-encoded CA certificate to write.

    Raises:
        CACertificateFileError: If the file cannot be written.

    Returns:
        The path to the written file.
    """
    try:
        CA_CERTS_DIR.mkdir(parents=True, exist_ok=True)
        path = CA_CERTS_DIR / f"backend-{identifier}-ca.pem"
        path.write_text(cert_pem, encoding="utf-8")
        path.chmod(0o644)
        return path
    except (PermissionError, OSError, IOError) as err:
        logger.exception("Failed to write backend CA cert for %s", identifier)
        raise CACertificateFileError(
            f"Unable to write backend CA cert for {identifier}"
        ) from err


def remove_backend_ca_cert(identifier: str) -> None:
    """Remove the per-relation backend CA certificate from disk.

    Does nothing if the file does not exist.

    Args:
        identifier: The same identifier used when writing the cert.
    """
    path = CA_CERTS_DIR / f"backend-{identifier}-ca.pem"
    path.unlink(missing_ok=True)
