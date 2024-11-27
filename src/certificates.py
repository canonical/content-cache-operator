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

logger = logging.getLogger(__name__)


def generate_certificate_requests(common_names: list[str]) -> list[CertificateRequestAttributes]:
    return [CertificateRequestAttributes(common_name=name) for name in common_names]


class TLSCertificatesManager:

    def __init__(
        self, user: str, certificates_path: Path, certificates: TLSCertificatesRequiresV4
    ) -> None:
        self.user = user
        self.certificates_path = certificates_path
        self.certificates = certificates

    def reconcile(self) -> bool:
        logger.info("Reconciling the certificate request and available")

        missing_certs = []
        for request in self.certificates.certificate_requests:
            provider_certificate, private_key = self.certificates.get_assigned_certificate(request)
            if not provider_certificate or not private_key:
                missing_certs.append[request.common_name]
                continue
            self._store_certificate(request.common_name, provider_certificate, private_key)

        if missing_certs:
            logger.info("Certificate not found for: %s", missing_certs)
            return False

        logger.info("Found all certificate requested")
        return True

    def _store_certificate(
        self, common_name: str, provider_certificate: ProviderCertificate, private_key: PrivateKey
    ) -> Path:
        logger.info("Store the certificate for %s", common_name)

        pem_file_content = f"{provider_certificate}\n{private_key}"
        pem_file_path = self.certificates_path / f"{common_name}.pem"
        pem_file_path.write_text(pem_file_content, encoding="utf-8")

        user = pwd.getpwnam(self.user)
        os.chown(pem_file_path, uid=user.pw_uid, gid=user.pw_gid)
        os.chmod(pem_file_path, 0o644)
        return pem_file_path
