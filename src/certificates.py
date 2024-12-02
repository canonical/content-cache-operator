# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manage the TLS Certificates."""

import logging
import os
import pwd
from pathlib import Path
from typing import Sequence

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


def load_certificates(
    common_names: Sequence[str],
    username: str,
    certificates_path: Path,
    certificates: TLSCertificatesRequiresV4,
) -> dict[str, Path]:
    """Store the certificates available.

    Args:
        common_names: The common name of the certificates to check if available and store.
        username: The name of the user to own the certificate file.
        certificates_path: The directory to store the certificates.
        certificates: The TLSCertificateRequiresV4 object.

    Raises:
        TLSCertificateIntegrationNotExistError: Unable to found the tls-certificate integration.
        TLSCertificateNotAvailableError: At least one certificate is not available.

    Returns:
        The mapping of certificate common name to the file path of the corresponding
        certificate. If the certificate is not available the entry will not exist in the
        mapping.
    """
    relation = certificates.charm.model.get_relation(certificates.relationship_name)
    if not relation:
        raise TLSCertificateIntegrationNotExistError("TLS certificate integration not found")

    logger.info("Loading the certificate available over tls-certificates integration")

    common_name_to_cert = {}
    for request in [CertificateRequestAttributes(common_name=name) for name in common_names]:
        provider_certificate, private_key = certificates.get_assigned_certificate(request)
        if not provider_certificate or not private_key:
            logger.warning("Certificate or private key not found for %s", request.common_name)
            raise TLSCertificateNotAvailableError(
                f"Certificate not available for {request.common_name}"
            )
        common_name_to_cert[request.common_name] = _store_certificate(
            request.common_name, provider_certificate, private_key, username, certificates_path
        )
    return common_name_to_cert


# The file operations will be tested in integration tests.
def _store_certificate(  # pragma: no cover
    common_name: str,
    provider_certificate: ProviderCertificate,
    private_key: PrivateKey,
    username: str,
    certificates_path: Path,
) -> Path:
    """Store a certificate and private key to file.

    The certificate and private key is saved to the same file.

    args:
        common_name: The common name of the certificate.
        provider_certificate: The certificate to store to file.
        private_key: The private key for the certificate.
        username: The name of the user to own the certificate file.
        certificates_path: The directory to store the certificates.

    Returns:
        The filepath of the stored certificate and private key.
    """
    logger.info("Store the certificate for %s", common_name)

    pem_file_content = f"{provider_certificate.certificate}\n{private_key}"
    pem_file_path = certificates_path / f"{common_name}.pem"

    try:
        user = pwd.getpwnam(username)
        certificates_path.mkdir(parents=True, exist_ok=True)
        os.chown(certificates_path, uid=user.pw_uid, gid=user.pw_gid)
        pem_file_path.write_text(pem_file_content, encoding="utf-8")
        os.chown(pem_file_path, uid=user.pw_uid, gid=user.pw_gid)
        os.chmod(pem_file_path, 0o644)
    except (PermissionError, OSError, IOError) as err:
        logger.exception("Failed to write the certificate to file for %s", common_name)
        raise TLSCertificateFileError(
            f"Unable to write certificate for {common_name} to file"
        ) from err
    return pem_file_path
