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


def _make_self_signed_cert(common_name: str = "localhost") -> tuple[str, str]:
    """Return a self-signed cert PEM and SHA-256 fingerprint."""
    import datetime
    import hashlib

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    der = cert.public_bytes(serialization.Encoding.DER)
    fingerprint = ":".join(f"{byte:02X}" for byte in hashlib.sha256(der).digest())
    return cert_pem, fingerprint


def test_find_cert_by_fingerprint_returns_matching_cert():
    """
    arrange: A list of PEM certs containing a match.
    act: Call find_cert_by_fingerprint with the matching fingerprint.
    assert: The matching PEM string is returned.
    """
    cert_pem, fingerprint = _make_self_signed_cert("match")
    other_pem, _ = _make_self_signed_cert("other")

    result = ca_certs.find_cert_by_fingerprint(fingerprint, [other_pem, cert_pem])

    assert result == cert_pem.strip()


def test_find_cert_by_fingerprint_returns_none_when_no_match():
    """
    arrange: A list of PEM certs with no match.
    act: Call find_cert_by_fingerprint with a non-matching fingerprint.
    assert: None is returned.
    """
    cert_pem, _ = _make_self_signed_cert()
    fingerprint = (
        "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:"
        "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
    )

    result = ca_certs.find_cert_by_fingerprint(fingerprint, [cert_pem])

    assert result is None


def test_find_cert_by_fingerprint_is_case_insensitive():
    """
    arrange: A cert and a lowercase fingerprint.
    act: Call find_cert_by_fingerprint.
    assert: The cert is found.
    """
    cert_pem, fingerprint = _make_self_signed_cert()

    result = ca_certs.find_cert_by_fingerprint(fingerprint.lower(), [cert_pem])

    assert result == cert_pem.strip()


def test_find_cert_by_fingerprint_skips_invalid_pem():
    """
    arrange: An invalid PEM followed by a valid cert.
    act: Call find_cert_by_fingerprint.
    assert: The valid cert is found without raising.
    """
    cert_pem, fingerprint = _make_self_signed_cert()

    result = ca_certs.find_cert_by_fingerprint(fingerprint, ["not-a-cert", cert_pem])

    assert result == cert_pem.strip()


def test_load_system_ca_certs_returns_list(monkeypatch, tmp_path):
    """
    arrange: A fake system CA bundle with two certs.
    act: Call load_system_ca_certs.
    assert: Both certs are returned.
    """
    cert1, _ = _make_self_signed_cert("ca1")
    cert2, _ = _make_self_signed_cert("ca2")
    bundle = tmp_path / "ca-certificates.crt"
    bundle.write_text(cert1 + "\n" + cert2, encoding="utf-8")
    monkeypatch.setattr("ca_certs.SYSTEM_CA_BUNDLE_PATH", bundle)

    assert ca_certs.load_system_ca_certs() == [cert1.strip(), cert2.strip()]


def test_load_system_ca_certs_returns_empty_when_no_bundle(monkeypatch, tmp_path):
    """
    arrange: No system CA bundle exists.
    act: Call load_system_ca_certs.
    assert: An empty list is returned.
    """
    monkeypatch.setattr("ca_certs.SYSTEM_CA_BUNDLE_PATH", tmp_path / "missing.crt")

    assert ca_certs.load_system_ca_certs() == []


def test_write_backend_ca_cert_creates_file_and_returns_path(tmp_path, monkeypatch):
    """
    arrange: A backend CA certificate PEM string.
    act: Call write_backend_ca_cert.
    assert: The expected file is created and returned.
    """
    monkeypatch.setattr("ca_certs.CA_CERTS_DIR", tmp_path)
    cert_pem, _ = _make_self_signed_cert()

    path = ca_certs.write_backend_ca_cert("8080", cert_pem)

    assert path == tmp_path / "backend-8080-ca.pem"
    assert path.read_text(encoding="utf-8") == cert_pem


def test_remove_backend_ca_cert_deletes_file(tmp_path, monkeypatch):
    """
    arrange: A backend CA cert file exists.
    act: Call remove_backend_ca_cert.
    assert: The file is deleted.
    """
    monkeypatch.setattr("ca_certs.CA_CERTS_DIR", tmp_path)
    cert_path = tmp_path / "backend-8080-ca.pem"
    cert_path.write_text("cert", encoding="utf-8")

    ca_certs.remove_backend_ca_cert("8080")

    assert not cert_path.exists()


def test_remove_backend_ca_cert_noop_when_missing(tmp_path, monkeypatch):
    """
    arrange: No backend CA cert file exists.
    act: Call remove_backend_ca_cert.
    assert: No exception is raised.
    """
    monkeypatch.setattr("ca_certs.CA_CERTS_DIR", tmp_path)

    ca_certs.remove_backend_ca_cert("8080")
