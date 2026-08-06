# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manage CA certificates for nginx backend trust."""

import logging
from pathlib import Path

from errors import CACertificateFileError

logger = logging.getLogger(__name__)

CA_CERTS_DIR = Path("/etc/nginx/certs")
CA_BUNDLE_PATH = CA_CERTS_DIR / "ca-bundle.pem"


def write_ca_cert(relation_id: int, certificates: list[str]) -> None:
    """Write CA certificates for a relation and regenerate the bundle.

    Args:
        relation_id: The Juju relation ID.
        certificates: The list of PEM-encoded CA certificate strings to trust.

    Raises:
        CACertificateFileError: If a file operation fails.
    """
    cert_path = _ca_cert_path(relation_id)
    try:
        CA_CERTS_DIR.mkdir(parents=True, exist_ok=True)
        cert_path.write_text("\n".join(certificates), encoding="utf-8")
    except (PermissionError, OSError, IOError) as err:
        logger.exception("Failed to write CA cert for relation %s", relation_id)
        raise CACertificateFileError(
            f"Unable to write CA certificate for relation {relation_id}"
        ) from err
    _regenerate_bundle()


def remove_ca_cert(relation_id: int) -> None:
    """Remove the CA certificate file for a relation and regenerate the bundle.

    Args:
        relation_id: The Juju relation ID.

    Raises:
        CACertificateFileError: If a file operation fails.
    """
    cert_path = _ca_cert_path(relation_id)
    try:
        cert_path.unlink(missing_ok=True)
    except (PermissionError, OSError, IOError) as err:
        logger.exception("Failed to remove CA cert for relation %s", relation_id)
        raise CACertificateFileError(
            f"Unable to remove CA certificate for relation {relation_id}"
        ) from err
    _regenerate_bundle()


def get_ca_bundle_path() -> Path | None:
    """Return the CA bundle path if it exists, else None.

    Returns:
        The path to the merged CA bundle, or None if no bundle exists.
    """
    return CA_BUNDLE_PATH if CA_BUNDLE_PATH.exists() else None


def _ca_cert_path(relation_id: int) -> Path:
    """Return the per-relation CA cert file path.

    Args:
        relation_id: The Juju relation ID.

    Returns:
        The path for the per-relation CA cert file.
    """
    return CA_CERTS_DIR / f"ca-{relation_id}.pem"


def _regenerate_bundle() -> None:
    """Concatenate all per-relation CA cert files into the bundle.

    Removes the bundle file if no per-relation files exist.

    Raises:
        CACertificateFileError: If a file operation fails.
    """
    try:
        cert_files = sorted(f for f in CA_CERTS_DIR.glob("ca-*.pem") if f != CA_BUNDLE_PATH)
        if not cert_files:
            CA_BUNDLE_PATH.unlink(missing_ok=True)
            return
        bundle_content = "\n".join(f.read_text(encoding="utf-8") for f in cert_files)
        CA_BUNDLE_PATH.write_text(bundle_content, encoding="utf-8")
    except (PermissionError, OSError, IOError) as err:
        logger.exception("Failed to regenerate CA bundle")
        raise CACertificateFileError("Unable to regenerate CA bundle") from err
