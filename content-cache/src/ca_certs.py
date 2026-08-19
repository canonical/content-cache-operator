# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manage CA certificates for nginx backend trust."""

import logging
from pathlib import Path

from errors import CACertificateFileError

logger = logging.getLogger(__name__)

CA_CERTS_DIR = Path("/etc/nginx/certs")
CA_BUNDLE_PATH = CA_CERTS_DIR / "ca-bundle.pem"


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
