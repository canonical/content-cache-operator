# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the ca_certs module."""

import pytest

import ca_certs

FAKE_SYSTEM_CA_CONTENT = "# fake system CA\n"


def test_write_ca_bundle_always_includes_system_cas():
    """
    arrange: No operator certs.
    act: Write an empty bundle.
    assert: The bundle file is created and contains the system CAs.
    """
    ca_certs.write_ca_bundle([])

    assert ca_certs.CA_BUNDLE_PATH.exists()
    assert FAKE_SYSTEM_CA_CONTENT in ca_certs.CA_BUNDLE_PATH.read_text()


def test_write_ca_bundle_appends_operator_certs():
    """
    arrange: Operator certs provided.
    act: Write the bundle.
    assert: The bundle contains both system CAs and the operator certs.
    """
    ca_certs.write_ca_bundle(["operator-cert-A", "operator-cert-B"])

    bundle = ca_certs.CA_BUNDLE_PATH.read_text()
    assert FAKE_SYSTEM_CA_CONTENT in bundle
    assert "operator-cert-A" in bundle
    assert "operator-cert-B" in bundle


def test_write_ca_bundle_replaces_previous():
    """
    arrange: A bundle already written with one operator cert.
    act: Overwrite the bundle with a different operator cert.
    assert: Only the new operator cert appears alongside the system CAs.
    """
    ca_certs.write_ca_bundle(["cert-old"])
    ca_certs.write_ca_bundle(["cert-new"])

    bundle = ca_certs.CA_BUNDLE_PATH.read_text()
    assert FAKE_SYSTEM_CA_CONTENT in bundle
    assert "cert-new" in bundle
    assert "cert-old" not in bundle


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
