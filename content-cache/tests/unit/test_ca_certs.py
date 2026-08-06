# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the ca_certs module."""

import pytest

import ca_certs


def test_write_ca_cert_creates_per_relation_file():
    """
    arrange: An empty certs directory.
    act: Write a CA cert for relation 42.
    assert: A per-relation file is created with the cert content.
    """
    ca_certs.write_ca_cert(42, ["cert-content-A"])

    per_relation_path = ca_certs.CA_CERTS_DIR / "ca-42.pem"
    assert per_relation_path.exists()
    assert "cert-content-A" in per_relation_path.read_text()


def test_write_ca_cert_regenerates_bundle():
    """
    arrange: An empty certs directory.
    act: Write CA certs for two relations.
    assert: The bundle file contains all certs from both relations.
    """
    ca_certs.write_ca_cert(1, ["cert-A"])
    ca_certs.write_ca_cert(2, ["cert-B"])

    bundle = ca_certs.CA_BUNDLE_PATH.read_text()
    assert "cert-A" in bundle
    assert "cert-B" in bundle


def test_write_ca_cert_multiple_certs_per_relation():
    """
    arrange: An empty certs directory.
    act: Write two CA certs for the same relation.
    assert: Both certs are written to the per-relation file.
    """
    ca_certs.write_ca_cert(1, ["cert-A", "cert-B"])

    per_relation_path = ca_certs.CA_CERTS_DIR / "ca-1.pem"
    content = per_relation_path.read_text()
    assert "cert-A" in content
    assert "cert-B" in content


def test_remove_ca_cert_deletes_per_relation_file():
    """
    arrange: A CA cert written for relation 42.
    act: Remove the cert for relation 42.
    assert: The per-relation file is deleted.
    """
    ca_certs.write_ca_cert(42, ["cert-content"])

    ca_certs.remove_ca_cert(42)

    assert not (ca_certs.CA_CERTS_DIR / "ca-42.pem").exists()


def test_remove_ca_cert_updates_bundle():
    """
    arrange: CA certs written for two relations.
    act: Remove one relation's cert.
    assert: The bundle no longer contains the removed cert; the remaining cert is still there.
    """
    ca_certs.write_ca_cert(1, ["cert-A"])
    ca_certs.write_ca_cert(2, ["cert-B"])

    ca_certs.remove_ca_cert(1)

    bundle = ca_certs.CA_BUNDLE_PATH.read_text()
    assert "cert-A" not in bundle
    assert "cert-B" in bundle


def test_remove_ca_cert_deletes_bundle_when_last_removed():
    """
    arrange: A CA cert written for one relation.
    act: Remove that relation's cert.
    assert: The bundle file is deleted (no more CA certs).
    """
    ca_certs.write_ca_cert(1, ["cert-A"])

    ca_certs.remove_ca_cert(1)

    assert not ca_certs.CA_BUNDLE_PATH.exists()


def test_remove_ca_cert_nonexistent_is_noop():
    """
    arrange: No certs written.
    act: Remove a cert for a relation that doesn't exist.
    assert: No error is raised.
    """
    ca_certs.remove_ca_cert(99)  # should not raise


def test_get_ca_bundle_path_returns_path_when_bundle_exists():
    """
    arrange: A CA cert written (bundle exists).
    act: Call get_ca_bundle_path.
    assert: Returns the bundle path.
    """
    ca_certs.write_ca_cert(1, ["cert-A"])

    result = ca_certs.get_ca_bundle_path()

    assert result == ca_certs.CA_BUNDLE_PATH


def test_get_ca_bundle_path_returns_none_when_no_bundle():
    """
    arrange: No certs written (bundle does not exist).
    act: Call get_ca_bundle_path.
    assert: Returns None.
    """
    result = ca_certs.get_ca_bundle_path()

    assert result is None


def test_write_ca_cert_bundle_has_correct_permissions():
    """
    arrange: An empty certs directory.
    act: Write a CA cert (triggering bundle regeneration).
    assert: The bundle file has 0o644 permissions.
    """
    ca_certs.write_ca_cert(1, ["cert-A"])

    mode = ca_certs.CA_BUNDLE_PATH.stat().st_mode & 0o777
    assert mode == 0o644


def test_write_ca_cert_raises_on_permission_error(monkeypatch):
    """
    arrange: Writing the cert file raises PermissionError.
    act: Call write_ca_cert.
    assert: CACertificateFileError is raised.
    """
    from pathlib import Path
    from unittest.mock import MagicMock

    from errors import CACertificateFileError

    mock_cert_path = MagicMock(spec=Path)
    mock_cert_path.write_text.side_effect = PermissionError("denied")
    mock_dir = MagicMock(spec=Path)
    mock_dir.__truediv__ = MagicMock(return_value=mock_cert_path)
    monkeypatch.setattr("ca_certs.CA_CERTS_DIR", mock_dir)

    with pytest.raises(CACertificateFileError):
        ca_certs.write_ca_cert(1, ["cert-A"])


def test_remove_ca_cert_raises_on_permission_error(monkeypatch):
    """
    arrange: Unlinking the cert file raises PermissionError.
    act: Call remove_ca_cert.
    assert: CACertificateFileError is raised.
    """
    from pathlib import Path
    from unittest.mock import MagicMock as _MagicMock

    from errors import CACertificateFileError

    mock_cert_path = _MagicMock(spec=Path)
    mock_cert_path.unlink.side_effect = PermissionError("denied")
    mock_dir = _MagicMock(spec=Path)
    mock_dir.__truediv__ = _MagicMock(return_value=mock_cert_path)
    monkeypatch.setattr("ca_certs.CA_CERTS_DIR", mock_dir)

    with pytest.raises(CACertificateFileError):
        ca_certs.remove_ca_cert(1)


def test_regenerate_bundle_raises_on_permission_error(monkeypatch):
    """
    arrange: Bundle write raises PermissionError after cert files are found.
    act: Call write_ca_cert which triggers bundle regeneration.
    assert: CACertificateFileError is raised.
    """
    from errors import CACertificateFileError

    # Write a cert file so glob finds it during bundle regeneration
    certs_dir = ca_certs.CA_CERTS_DIR
    certs_dir.mkdir(parents=True, exist_ok=True)
    (certs_dir / "ca-1.pem").write_text("cert-A")

    # Creating a directory at the bundle path causes write_text to raise IsADirectoryError
    ca_certs.CA_BUNDLE_PATH.mkdir(parents=True, exist_ok=True)

    with pytest.raises(CACertificateFileError):
        ca_certs.write_ca_cert(2, ["cert-B"])
