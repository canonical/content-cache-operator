# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manage the TLS Certificates."""

import logging
import os
import pwd
from pathlib import Path

from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateRequestAttributes,
    PrivateKey,
    ProviderCertificate,
    TLSCertificatesRequiresV4,
)

from errors import (
    TLSCertificateFileError,
    TLSCertificateIntegrationNotExistError,
    TLSCertificateNotAvailableError,
)

logger = logging.getLogger(__name__)

FRONTEND_CERT_COMMON_NAME = "content-cache-charm"


def write_certificate(
    username: str,
    certificates_path: Path,
    certificates: TLSCertificatesRequiresV4,
) -> Path:
    """Write the frontend TLS certificate to disk.

    Looks up the certificate for the fixed common name ``content-cache-charm``
    and stores the leaf certificate, any intermediate chain certificates, and
    the private key in a single PEM file.

    Args:
        username: The OS user that should own the certificate file.
        certificates_path: Directory to write the certificate into.
        certificates: The TLSCertificatesRequiresV4 object.

    Raises:
        TLSCertificateIntegrationNotExistError: No tls-certificates relation found.
        TLSCertificateNotAvailableError: Certificate or key not yet issued.

    Returns:
        Path to the written PEM file.
    """
    relation = certificates.charm.model.get_relation(certificates.relationship_name)
    if not relation:
        raise TLSCertificateIntegrationNotExistError("TLS certificate integration not found")

    request = CertificateRequestAttributes(common_name=FRONTEND_CERT_COMMON_NAME)
    provider_certificate, private_key = certificates.get_assigned_certificate(request)
    if not provider_certificate or not private_key:
        logger.warning("Certificate or private key not found for %s", FRONTEND_CERT_COMMON_NAME)
        raise TLSCertificateNotAvailableError(
            f"Certificate not available for {FRONTEND_CERT_COMMON_NAME}"
        )
    return _store_certificate(provider_certificate, private_key, username, certificates_path)


# The file operations will be tested in integration tests.
def _store_certificate(  # pragma: no cover
    provider_certificate: ProviderCertificate,
    private_key: PrivateKey,
    username: str,
    certificates_path: Path,
) -> Path:
    """Store the certificate, chain, and private key to a single PEM file.

    args:
        provider_certificate: The leaf certificate (and optional chain) to store.
        private_key: The private key for the certificate.
        username: The name of the user to own the certificate file.
        certificates_path: The directory to store the certificates.

    Returns:
        The filepath of the stored PEM file.
    """
    logger.info("Storing the frontend TLS certificate")

    parts = [str(provider_certificate.certificate)]
    if provider_certificate.chain:
        # chain[0] is the leaf cert itself (same as provider_certificate.certificate);
        # chain[1:] contains intermediate CA certs that nginx needs to complete the chain.
        parts.extend(str(c) for c in provider_certificate.chain[1:])
    parts.append(str(private_key))
    pem_file_content = "\n".join(parts)
    pem_file_path = certificates_path / f"{FRONTEND_CERT_COMMON_NAME}.pem"

    try:
        user = pwd.getpwnam(username)
        certificates_path.mkdir(parents=True, exist_ok=True)
        os.chown(certificates_path, uid=user.pw_uid, gid=user.pw_gid)
        pem_file_path.write_text(pem_file_content, encoding="utf-8")
        os.chown(pem_file_path, uid=user.pw_uid, gid=user.pw_gid)
        os.chmod(pem_file_path, 0o600)
    except (PermissionError, OSError, IOError) as err:
        logger.exception("Failed to write the frontend TLS certificate to file")
        raise TLSCertificateFileError("Unable to write frontend TLS certificate to file") from err
    return pem_file_path
