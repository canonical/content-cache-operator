# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the ca_certs module."""

import pytest

import ca_certs


def test_write_ca_bundle_creates_bundle_file():
    """
    arrange: An empty certs directory.
    act: Write a bundle with one cert.
    assert: The bundle file is created with the cert content.
    """
    ca_certs.write_ca_bundle(["cert-content-A"])

    assert ca_certs.CA_BUNDLE_PATH.exists()
    assert "cert-content-A" in ca_certs.CA_BUNDLE_PATH.read_text()


def test_write_ca_bundle_multiple_certs():
    """
    arrange: An empty certs directory.
    act: Write a bundle with two certs.
    assert: The bundle file contains both certs.
    """
    ca_certs.write_ca_bundle(["cert-A", "cert-B"])

    bundle = ca_certs.CA_BUNDLE_PATH.read_text()
    assert "cert-A" in bundle
    assert "cert-B" in bundle


def test_write_ca_bundle_replaces_previous():
    """
    arrange: A bundle already written with one cert.
    act: Overwrite the bundle with a different cert.
    assert: Only the new cert is in the bundle.
    """
    ca_certs.write_ca_bundle(["cert-old"])
    ca_certs.write_ca_bundle(["cert-new"])

    bundle = ca_certs.CA_BUNDLE_PATH.read_text()
    assert "cert-new" in bundle
    assert "cert-old" not in bundle


def test_write_ca_bundle_empty_removes_file():
    """
    arrange: A bundle already written.
    act: Write an empty list.
    assert: The bundle file is removed.
    """
    ca_certs.write_ca_bundle(["cert-A"])

    ca_certs.write_ca_bundle([])

    assert not ca_certs.CA_BUNDLE_PATH.exists()


def test_write_ca_bundle_empty_noop_when_no_file():
    """
    arrange: No bundle exists.
    act: Write an empty list.
    assert: No error is raised and no file is created.
    """
    ca_certs.write_ca_bundle([])  # should not raise

    assert not ca_certs.CA_BUNDLE_PATH.exists()


def test_get_ca_bundle_path_returns_path_when_bundle_exists():
    """
    arrange: A bundle written.
    act: Call get_ca_bundle_path.
    assert: Returns the bundle path.
    """
    ca_certs.write_ca_bundle(["cert-A"])

    result = ca_certs.get_ca_bundle_path()

    assert result == ca_certs.CA_BUNDLE_PATH


def test_get_ca_bundle_path_returns_none_when_no_bundle():
    """
    arrange: No bundle written.
    act: Call get_ca_bundle_path.
    assert: Returns None.
    """
    result = ca_certs.get_ca_bundle_path()

    assert result is None


def test_write_ca_bundle_has_correct_permissions():
    """
    arrange: An empty certs directory.
    act: Write a bundle.
    assert: The bundle file has 0o644 permissions.
    """
    ca_certs.write_ca_bundle(["cert-A"])

    mode = ca_certs.CA_BUNDLE_PATH.stat().st_mode & 0o777
    assert mode == 0o644


def test_write_ca_bundle_raises_on_permission_error(monkeypatch):
    """
    arrange: Writing the bundle file raises PermissionError.
    act: Call write_ca_bundle.
    assert: CACertificateFileError is raised.
    """
    from pathlib import Path
    from unittest.mock import MagicMock

    from errors import CACertificateFileError

    mock_bundle_path = MagicMock(spec=Path)
    mock_bundle_path.write_text.side_effect = PermissionError("denied")
    mock_dir = MagicMock(spec=Path)
    mock_dir.mkdir = MagicMock()
    monkeypatch.setattr("ca_certs.CA_CERTS_DIR", mock_dir)
    monkeypatch.setattr("ca_certs.CA_BUNDLE_PATH", mock_bundle_path)

    with pytest.raises(CACertificateFileError):
        ca_certs.write_ca_bundle(["cert-A"])
