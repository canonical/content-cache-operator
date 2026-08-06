# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the ca_certs module."""

from pathlib import Path

import pytest

import ca_certs


@pytest.fixture(name="patch_ca_certs_dir")
def patch_ca_certs_dir_fixture(monkeypatch, tmp_path: Path) -> Path:
    """Patch the CA certs directory to a temporary path."""
    certs_dir = tmp_path / "certs"
    monkeypatch.setattr("ca_certs.CA_CERTS_DIR", certs_dir)
    monkeypatch.setattr("ca_certs.CA_BUNDLE_PATH", certs_dir / "ca-bundle.pem")
    return certs_dir


def test_write_ca_cert_creates_per_relation_file(patch_ca_certs_dir: Path):
    """
    arrange: An empty certs directory.
    act: Write a CA cert for relation 42.
    assert: A per-relation file is created with the cert content.
    """
    ca_certs.write_ca_cert(42, ["cert-content-A"])

    per_relation_path = patch_ca_certs_dir / "ca-42.pem"
    assert per_relation_path.exists()
    assert "cert-content-A" in per_relation_path.read_text()


def test_write_ca_cert_regenerates_bundle(patch_ca_certs_dir: Path):
    """
    arrange: An empty certs directory.
    act: Write CA certs for two relations.
    assert: The bundle file contains all certs from both relations.
    """
    ca_certs.write_ca_cert(1, ["cert-A"])
    ca_certs.write_ca_cert(2, ["cert-B"])

    bundle = (patch_ca_certs_dir / "ca-bundle.pem").read_text()
    assert "cert-A" in bundle
    assert "cert-B" in bundle


def test_write_ca_cert_multiple_certs_per_relation(patch_ca_certs_dir: Path):
    """
    arrange: An empty certs directory.
    act: Write two CA certs for the same relation.
    assert: Both certs are written to the per-relation file.
    """
    ca_certs.write_ca_cert(1, ["cert-A", "cert-B"])

    per_relation_path = patch_ca_certs_dir / "ca-1.pem"
    content = per_relation_path.read_text()
    assert "cert-A" in content
    assert "cert-B" in content


def test_remove_ca_cert_deletes_per_relation_file(patch_ca_certs_dir: Path):
    """
    arrange: A CA cert written for relation 42.
    act: Remove the cert for relation 42.
    assert: The per-relation file is deleted.
    """
    ca_certs.write_ca_cert(42, ["cert-content"])

    ca_certs.remove_ca_cert(42)

    assert not (patch_ca_certs_dir / "ca-42.pem").exists()


def test_remove_ca_cert_updates_bundle(patch_ca_certs_dir: Path):
    """
    arrange: CA certs written for two relations.
    act: Remove one relation's cert.
    assert: The bundle no longer contains the removed cert; the remaining cert is still there.
    """
    ca_certs.write_ca_cert(1, ["cert-A"])
    ca_certs.write_ca_cert(2, ["cert-B"])

    ca_certs.remove_ca_cert(1)

    bundle = (patch_ca_certs_dir / "ca-bundle.pem").read_text()
    assert "cert-A" not in bundle
    assert "cert-B" in bundle


def test_remove_ca_cert_deletes_bundle_when_last_removed(patch_ca_certs_dir: Path):
    """
    arrange: A CA cert written for one relation.
    act: Remove that relation's cert.
    assert: The bundle file is deleted (no more CA certs).
    """
    ca_certs.write_ca_cert(1, ["cert-A"])

    ca_certs.remove_ca_cert(1)

    assert not (patch_ca_certs_dir / "ca-bundle.pem").exists()


def test_remove_ca_cert_nonexistent_is_noop(patch_ca_certs_dir: Path):
    """
    arrange: No certs written.
    act: Remove a cert for a relation that doesn't exist.
    assert: No error is raised.
    """
    ca_certs.remove_ca_cert(99)  # should not raise


def test_get_ca_bundle_path_returns_path_when_bundle_exists(patch_ca_certs_dir: Path):
    """
    arrange: A CA cert written (bundle exists).
    act: Call get_ca_bundle_path.
    assert: Returns the bundle path.
    """
    ca_certs.write_ca_cert(1, ["cert-A"])

    result = ca_certs.get_ca_bundle_path()

    assert result == patch_ca_certs_dir / "ca-bundle.pem"


def test_get_ca_bundle_path_returns_none_when_no_bundle(patch_ca_certs_dir: Path):
    """
    arrange: No certs written (bundle does not exist).
    act: Call get_ca_bundle_path.
    assert: Returns None.
    """
    result = ca_certs.get_ca_bundle_path()

    assert result is None
