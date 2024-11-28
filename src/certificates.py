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

from errors import TLSCertificateFileError

logger = logging.getLogger(__name__)


def _generate_certificate_requests(
    common_names: Sequence[str],
) -> list[CertificateRequestAttributes]:
    """Generate the certificate requests.

    Args:
        common_names: A list of common name for the certificates to request.

    Returns:
        The certificate requests.
    """
    return [CertificateRequestAttributes(common_name=name) for name in common_names]


class TLSCertificatesManager:
    """Manage the TLS certificate integration.

    Attributes:
        user: The user to own the certificates.
        certificates_path: The directory to store the certificates.
        certificates: The TLS certificate integration V4 library class.
    """

    def __init__(
        self, user: str, certificates_path: Path, certificates: TLSCertificatesRequiresV4
    ) -> None:
        """Construct the TLSCertificateManager.

        Args:
            user: The user to own the certificates.
            certificates_path: The directory to store the certificates.
            certificates: The TLS certificate integration V4 library class.
        """
        self.user = user
        self.certificates_path = certificates_path
        self.certificates = certificates

    def integration_exists(self) -> bool:
        """Whether the TLS certificate integration exists.

        Returns:
            Whether the TLS certificate integration exists.
        """
        relation = self.certificates.charm.model.get_relation(self.certificates.relationship_name)
        if not relation:
            return False
        return True

    def load_certificates(self, common_names: Sequence[str]) -> dict[str, Path]:
        """Store the certificates available.

        Args:
            common_names: The common name of the certificates to check if available and store.

        Returns:
            The mapping of certificate common name to the file path of the corresponding
            certificate. If the certificate is not available the entry will not exist in the
            mapping.
        """
        logger.info("Loading the certificate available")

        common_name_to_cert = {}
        for request in _generate_certificate_requests(common_names):
            provider_certificate, private_key = self.certificates.get_assigned_certificate(request)
            if not provider_certificate or not private_key:
                logger.warning("Certificate or private key not found for %s", request.common_name)
                continue
            common_name_to_cert[request.common_name] = self._store_certificate(
                request.common_name, provider_certificate, private_key
            )
        return common_name_to_cert

    # The file operations will be tested in integration tests.
    def _store_certificate(  # pragma: no cover
        self, common_name: str, provider_certificate: ProviderCertificate, private_key: PrivateKey
    ) -> Path:
        """Store a certificate and private key to file.

        The certificate and private key is saved to the same file.

        args:
            common_name: The common name of the certificate.
            provider_certificate: The certificate to store to file.
            private_key: The private key for the certificate.

        Returns:
            The filepath of the stored certificate and private key.
        """
        logger.info("Store the certificate for %s", common_name)

        pem_file_content = f"{provider_certificate.certificate}\n{private_key}"
        pem_file_path = self.certificates_path / f"{common_name}.pem"

        try:
            user = pwd.getpwnam(self.user)
            self.certificates_path.mkdir(parents=True, exist_ok=True)
            os.chown(self.certificates_path, uid=user.pw_uid, gid=user.pw_gid)
            pem_file_path.write_text(pem_file_content, encoding="utf-8")
            os.chown(pem_file_path, uid=user.pw_uid, gid=user.pw_gid)
            os.chmod(pem_file_path, 0o644)
        except (PermissionError, OSError, IOError) as err:
            logger.exception("Failed to write the certificate to file for %s", common_name)
            raise TLSCertificateFileError(
                f"Unable to write certificate for {common_name} to file"
            ) from err
        return pem_file_path
