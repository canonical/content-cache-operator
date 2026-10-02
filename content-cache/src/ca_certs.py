# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manage CA certificates for nginx backend trust."""

import logging
from pathlib import Path

from errors import CACertificateFileError

logger = logging.getLogger(__name__)

CA_CERTS_DIR = Path("/etc/nginx/certs")
CA_BUNDLE_PATH = CA_CERTS_DIR / "ca-bundle.pem"

# Ubuntu system CA bundle — always included as the base trust store so that
# publicly trusted certificates (e.g. Let's Encrypt / ISRG Root X1) are
# verified without manual configuration.
SYSTEM_CA_BUNDLE_PATH = Path("/etc/ssl/certs/ca-certificates.crt")


def write_ca_bundle(certificates: list[str]) -> None:
    """Write the combined CA bundle: system CAs plus any operator-supplied certs.

    The bundle always includes the Ubuntu system CA store so publicly trusted
    certificates (e.g. Let's Encrypt) are verified without manual configuration.
    Any PEM strings in *certificates* (from ``receive-ca-cert`` relations) are
    appended, allowing private / self-signed backend CAs to be trusted as well.

    Args:
        certificates: PEM-encoded CA certificate strings to append to the system
            CAs.  May be empty — the system CAs are always written.

    Raises:
        CACertificateFileError: If a file operation fails.
    """
    try:
        system_cas = SYSTEM_CA_BUNDLE_PATH.read_text(encoding="utf-8")
        CA_CERTS_DIR.mkdir(parents=True, exist_ok=True)
        parts = [system_cas] + certificates
        CA_BUNDLE_PATH.write_text("\n".join(parts), encoding="utf-8")
        CA_BUNDLE_PATH.chmod(0o644)
    except (PermissionError, OSError, IOError) as err:
        logger.exception("Failed to write CA bundle")
        raise CACertificateFileError("Unable to write CA bundle") from err
