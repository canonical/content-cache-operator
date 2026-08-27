# HTTPS Backend certificate_transfer Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `certificate_transfer` as a requirer relation to the content-cache charm so nginx can verify HTTPS backend connections using the received CA certificates.

**Architecture:** Per-relation CA cert files are stored at `/etc/nginx/certs/ca-<relation_id>.pem`; a merged bundle at `/etc/nginx/certs/ca-bundle.pem` is regenerated on every change and referenced by `proxy_ssl_trusted_certificate` in the nginx location config. HTTPS backends are detected from the URL scheme; if HTTPS backends are configured but no bundle exists, the charm emits `WaitingStatus`.

**Tech Stack:** ops, `charms.certificate_transfer_interface.v1.certificate_transfer`, python-nginx, pytest

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Fetch lib | `content-cache/lib/charms/certificate_transfer_interface/v1/certificate_transfer.py` | Official charm library for the relation |
| Create | `content-cache/src/ca_certs.py` | Write/remove per-relation CA cert files; regenerate merged bundle |
| Modify | `content-cache/src/errors.py` | Add `CACertificateFileError` |
| Modify | `content-cache/src/charm.py` | Handle `certificate_set_updated` / `certificates_removed`; pass CA bundle to nginx; WaitingStatus |
| Modify | `content-cache/src/nginx_manager.py` | Accept `ca_bundle_path` and emit `proxy_ssl_*` directives for HTTPS backends |
| Modify | `content-cache/charmcraft.yaml` | Add `certificate-transfer` requires relation |
| Modify | `content-cache/tests/unit/conftest.py` | Patch `ca_certs.CA_CERTS_DIR` in fixtures |
| Create | `content-cache/tests/unit/test_ca_certs.py` | Unit tests for ca_certs module |
| Modify | `content-cache/tests/unit/test_charm.py` | Tests for cert events and WaitingStatus |
| Modify | `content-cache/tests/unit/test_nginx_manager.py` | Tests for proxy_ssl directives |
| Modify | `content-cache/tests/integration/test_tls_cert.py` | Replace skipped placeholders with real HTTPS backend tests |
| Modify | `docs/how-to/enable-https.md` | Document certificate_transfer integration |
| Modify | `docs/explanation/charm-design.md` | Document the certificate-transfer relation |

---

## Task 1: Fetch the certificate_transfer library and register the relation

**Files:**
- Fetch: `content-cache/lib/charms/certificate_transfer_interface/v1/certificate_transfer.py`
- Modify: `content-cache/charmcraft.yaml`

- [ ] **Step 1: Fetch the charm library**

```bash
cd content-cache
charmcraft fetch-lib charms.certificate_transfer_interface.v1.certificate_transfer
```

Expected: `content-cache/lib/charms/certificate_transfer_interface/v1/certificate_transfer.py` created.

- [ ] **Step 2: Add the relation to charmcraft.yaml**

In `content-cache/charmcraft.yaml`, find the `requires:` section and add:

```yaml
requires:
  certificates:
    interface: tls-certificates
  certificate-transfer:
    interface: certificate_transfer
```

- [ ] **Step 3: Commit**

```bash
git add content-cache/lib/charms/certificate_transfer_interface/ content-cache/charmcraft.yaml
git commit -m "chore: fetch certificate_transfer library and register relation"
```

---

## Task 2: Add CACertificateFileError to errors.py

**Files:**
- Modify: `content-cache/src/errors.py`

- [ ] **Step 1: Add the error class**

At the end of `content-cache/src/errors.py`, add:

```python
class CACertificateFileError(Exception):
    """Represents failure in writing or removing a CA certificate file."""
```

- [ ] **Step 2: Run lint**

```bash
cd content-cache && tox -e lint
```

Expected: `lint: OK`

- [ ] **Step 3: Commit**

```bash
git add content-cache/src/errors.py
git commit -m "feat: add CACertificateFileError to errors module"
```

---

## Task 3: Create ca_certs.py with TDD

**Files:**
- Create: `content-cache/src/ca_certs.py`
- Create: `content-cache/tests/unit/test_ca_certs.py`

- [ ] **Step 1: Write the failing tests**

Create `content-cache/tests/unit/test_ca_certs.py`:

```python
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the ca_certs module."""

from pathlib import Path

import pytest

import ca_certs
from errors import CACertificateFileError


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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd content-cache && tox -e unit -- tests/unit/test_ca_certs.py -v
```

Expected: `ModuleNotFoundError: No module named 'ca_certs'`

- [ ] **Step 3: Implement ca_certs.py**

Create `content-cache/src/ca_certs.py`:

```python
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
        cert_files = sorted(CA_CERTS_DIR.glob("ca-*.pem"))
        if not cert_files:
            CA_BUNDLE_PATH.unlink(missing_ok=True)
            return
        bundle_content = "\n".join(f.read_text(encoding="utf-8") for f in cert_files)
        CA_BUNDLE_PATH.write_text(bundle_content, encoding="utf-8")
    except (PermissionError, OSError, IOError) as err:
        logger.exception("Failed to regenerate CA bundle")
        raise CACertificateFileError("Unable to regenerate CA bundle") from err
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd content-cache && tox -e unit -- tests/unit/test_ca_certs.py -v
```

Expected: all 9 tests PASS.

- [ ] **Step 5: Run full unit tests and lint**

```bash
cd content-cache && tox -e unit,lint
```

Expected: `unit: OK`, `lint: OK`

- [ ] **Step 6: Commit**

```bash
git add content-cache/src/ca_certs.py content-cache/tests/unit/test_ca_certs.py
git commit -m "feat: add ca_certs module for CA certificate storage and bundle management"
```

---

## Task 4: Update nginx_manager.py to emit proxy_ssl directives

**Files:**
- Modify: `content-cache/src/nginx_manager.py`
- Modify: `content-cache/tests/unit/test_nginx_manager.py`

- [ ] **Step 1: Write failing tests**

In `content-cache/tests/unit/test_nginx_manager.py`, add after the existing location config key tests:

```python
def test_get_location_config_keys_https_with_ca_bundle(patch_nginx_manager: None, tmp_path):
    """
    arrange: A LocationConfig with https backends and a CA bundle path.
    act: Call _get_location_config_keys with ca_bundle_path set.
    assert: proxy_ssl_trusted_certificate, proxy_ssl_verify on, proxy_ssl_server_name off present.
    """
    ca_bundle = tmp_path / "ca-bundle.pem"
    ca_bundle.write_text("cert", encoding="utf-8")
    data = {**SAMPLE_INTEGRATION_DATA, "backends": '["https://10.10.1.1:443"]'}
    config = LocationConfig.from_integration_data(data)
    upstream = "test-upstream"

    keys = nginx_manager._get_location_config_keys(config, upstream, ca_bundle_path=ca_bundle)

    key_strings = [k.as_strings for k in keys]
    assert any("proxy_ssl_trusted_certificate" in s for s in key_strings)
    assert any("proxy_ssl_verify" in s and "on" in s for s in key_strings)
    assert any("proxy_ssl_server_name" in s and "off" in s for s in key_strings)


def test_get_location_config_keys_https_without_ca_bundle(patch_nginx_manager: None):
    """
    arrange: A LocationConfig with https backends but no CA bundle path.
    act: Call _get_location_config_keys with ca_bundle_path=None.
    assert: No proxy_ssl directives in the keys.
    """
    data = {**SAMPLE_INTEGRATION_DATA, "backends": '["https://10.10.1.1:443"]'}
    config = LocationConfig.from_integration_data(data)

    keys = nginx_manager._get_location_config_keys(config, "upstream", ca_bundle_path=None)

    key_strings = [k.as_strings for k in keys]
    assert not any("proxy_ssl" in s for s in key_strings)


def test_get_location_config_keys_http_ignores_ca_bundle(patch_nginx_manager: None, tmp_path):
    """
    arrange: A LocationConfig with http backends and a CA bundle path provided.
    act: Call _get_location_config_keys.
    assert: No proxy_ssl directives added for http backends.
    """
    ca_bundle = tmp_path / "ca-bundle.pem"
    ca_bundle.write_text("cert", encoding="utf-8")
    config = LocationConfig.from_integration_data(SAMPLE_INTEGRATION_DATA)

    keys = nginx_manager._get_location_config_keys(config, "upstream", ca_bundle_path=ca_bundle)

    key_strings = [k.as_strings for k in keys]
    assert not any("proxy_ssl" in s for s in key_strings)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd content-cache && tox -e unit -- tests/unit/test_nginx_manager.py::test_get_location_config_keys_https_with_ca_bundle tests/unit/test_nginx_manager.py::test_get_location_config_keys_https_without_ca_bundle tests/unit/test_nginx_manager.py::test_get_location_config_keys_http_ignores_ca_bundle -v
```

Expected: FAIL — `_get_location_config_keys() got an unexpected keyword argument 'ca_bundle_path'`

- [ ] **Step 3: Update `_get_location_config_keys` in nginx_manager.py**

Find the function `_get_location_config_keys` (around line 490) and replace it with:

```python
def _get_location_config_keys(
    config: LocationConfig,
    upstream: str,
    ca_bundle_path: Path | None = None,
) -> tuple[nginx.Key, ...]:
    """Create the nginx keys for location configuration.

    Args:
        config: The location configurations.
        upstream: The upstream hostname for the backends.
        ca_bundle_path: Path to the CA bundle for proxy SSL verification, or None.

    Returns:
        The nginx.Key for the Location configuration.
    """
    scheme = config.backends[0].scheme
    keys: list[nginx.Key] = [
        nginx.Key("proxy_pass", f"{scheme}://{upstream}/"),
    ]

    if scheme == "https" and ca_bundle_path is not None:
        keys.extend(
            [
                nginx.Key("proxy_ssl_trusted_certificate", str(ca_bundle_path)),
                nginx.Key("proxy_ssl_verify", "on"),
                nginx.Key("proxy_ssl_server_name", "off"),
            ]
        )

    for cache_valid in config.proxy_cache_valid:
        keys.append(nginx.Key("proxy_cache_valid", cache_valid))

    return tuple(keys)
```

- [ ] **Step 4: Thread `ca_bundle_path` through the call chain**

Update `_create_virtualhost_config` signature (around line 370) — add `ca_bundle_path: Path | None = None`:

```python
def _create_virtualhost_config(
    identifier: str,
    port: int,
    configuration: LocationConfig,
    instance_name: str,
    ca_bundle_path: Path | None = None,
) -> str:
    """Create the nginx configuration for a port.

    Args:
        identifier: The identifier for the virtualhost.
        port: The TCP port nginx should listen on for this backend.
        configuration: The configuration of the backend.
        instance_name: The name of this instance.
        ca_bundle_path: Path to the CA bundle for proxy SSL verification, or None.

    Raises:
        NginxConfigurationError: Failed to convert the configuration to nginx format.
    """
```

Inside the same function, update the `_get_location_config_keys` call:

```python
        location_keys = _get_location_config_keys(configuration, upstream, ca_bundle_path=ca_bundle_path)
```

Update `update_and_load_config` signature — add `ca_bundle_path: Path | None = None`:

```python
def update_and_load_config(
    configuration: dict[int, tuple[int, LocationConfig]],
    instance_name: str,
    ca_bundle_path: Path | None = None,
) -> None:
    """Update the nginx configuration files and load them.

    Args:
        configuration: The nginx locations configurations keyed by relation ID.
            Each value is a tuple of (port, LocationConfig).
        instance_name: The name of this instance.
        ca_bundle_path: Path to the CA bundle for proxy SSL verification, or None.

    Raises:
        NginxConfigurationAggregateError: All failures related to creating nginx configuration.
        NginxFileError: File operation errors while updating nginx configuration files.
    """
```

Inside `update_and_load_config`, update the `_create_virtualhost_config` call:

```python
            vhost_healthcheck_worker_lua_code = _create_virtualhost_config(
                identifier, port, config, instance_name, ca_bundle_path=ca_bundle_path
            )
```

Also add `from pathlib import Path` to the imports at the top of `nginx_manager.py` if not already present (check — it's already imported since `NGINX_MAIN_CONF_PATH = Path(...)`).

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd content-cache && tox -e unit,lint
```

Expected: all tests PASS, `lint: OK`

- [ ] **Step 6: Commit**

```bash
git add content-cache/src/nginx_manager.py content-cache/tests/unit/test_nginx_manager.py
git commit -m "feat: add proxy_ssl directives for HTTPS backends in nginx config"
```

---

## Task 5: Update charm.py to handle certificate_transfer events

**Files:**
- Modify: `content-cache/src/charm.py`
- Modify: `content-cache/tests/unit/conftest.py`
- Modify: `content-cache/tests/unit/test_charm.py`

- [ ] **Step 1: Patch `ca_certs.CA_CERTS_DIR` in conftest**

In `content-cache/tests/unit/conftest.py`, add to the imports:

```python
import ca_certs
```

Add a new fixture and update the `mock_nginx_manager_fixture` to also mock `ca_certs`:

```python
@pytest.fixture(name="patch_ca_certs", scope="function", autouse=True)
def patch_ca_certs_fixture(monkeypatch, tmp_path: Path) -> None:
    """Patch the ca_certs module to use a temporary directory."""
    certs_dir = tmp_path / "certs"
    monkeypatch.setattr("ca_certs.CA_CERTS_DIR", certs_dir)
    monkeypatch.setattr("ca_certs.CA_BUNDLE_PATH", certs_dir / "ca-bundle.pem")
    monkeypatch.setattr("charm.ca_certs.CA_CERTS_DIR", certs_dir)
    monkeypatch.setattr("charm.ca_certs.CA_BUNDLE_PATH", certs_dir / "ca-bundle.pem")
```

- [ ] **Step 2: Write failing tests**

In `content-cache/tests/unit/test_charm.py`, add:

```python
CERT_TRANSFER_INTEGRATION_NAME = "certificate-transfer"
SAMPLE_CA_CERT = "-----BEGIN CERTIFICATE-----\nMIIFake\n-----END CERTIFICATE-----"


def test_certificate_available_writes_cert_and_reloads(
    harness: Harness, charm: ContentCacheCharm, mock_nginx_manager: MagicMock, tmp_path
):
    """
    arrange: A charm with an active cache-config relation.
    act: Fire a certificate_set_updated event with a CA cert.
    assert: The CA cert file is written and nginx config is reloaded.
    """
    import ca_certs

    harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )
    assert charm.unit.status == ops.ActiveStatus()

    rel_id = harness.add_relation(CERT_TRANSFER_INTEGRATION_NAME, remote_app="cert-provider")
    harness.update_relation_data(
        rel_id, "cert-provider", {"certificates": f'["{SAMPLE_CA_CERT}"]'}
    )

    bundle_path = ca_certs.get_ca_bundle_path()
    assert bundle_path is not None
    assert SAMPLE_CA_CERT in bundle_path.read_text()


def test_certificate_removed_deletes_cert_and_sets_waiting(
    harness: Harness, charm: ContentCacheCharm, mock_nginx_manager: MagicMock
):
    """
    arrange: A charm with an active cache-config relation using HTTPS backends and a CA cert.
    act: Remove the certificate_transfer relation.
    assert: The CA bundle is deleted and charm moves to WaitingStatus.
    """
    import ca_certs
    from tests.unit.conftest import BACKENDS_FIELD_NAME

    https_data = {
        **SAMPLE_INTEGRATION_DATA,
        BACKENDS_FIELD_NAME: '["https://10.10.1.1:443"]',
    }
    harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=https_data,
    )
    rel_id = harness.add_relation(CERT_TRANSFER_INTEGRATION_NAME, remote_app="cert-provider")
    harness.update_relation_data(
        rel_id, "cert-provider", {"certificates": f'["{SAMPLE_CA_CERT}"]'}
    )

    harness.remove_relation(rel_id)

    assert ca_certs.get_ca_bundle_path() is None
    assert isinstance(charm.unit.status, ops.WaitingStatus)


def test_https_backends_without_ca_bundle_sets_waiting(
    harness: Harness, charm: ContentCacheCharm, mock_nginx_manager: MagicMock
):
    """
    arrange: A charm with no certificate_transfer relation.
    act: Add a cache-config relation with HTTPS backends.
    assert: Charm enters WaitingStatus waiting for CA certificate.
    """
    from tests.unit.conftest import BACKENDS_FIELD_NAME

    https_data = {
        **SAMPLE_INTEGRATION_DATA,
        BACKENDS_FIELD_NAME: '["https://10.10.1.1:443"]',
    }
    harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=https_data,
    )

    assert isinstance(charm.unit.status, ops.WaitingStatus)
    assert "CA certificate" in str(charm.unit.status.message)


def test_http_backends_without_ca_bundle_stays_active(
    harness: Harness, charm: ContentCacheCharm, mock_nginx_manager: MagicMock
):
    """
    arrange: A charm with no certificate_transfer relation.
    act: Add a cache-config relation with HTTP backends.
    assert: Charm remains Active (no CA cert required for HTTP).
    """
    harness.add_relation(
        CACHE_CONFIG_INTEGRATION_NAME,
        remote_app="config",
        app_data=SAMPLE_INTEGRATION_DATA,
    )

    assert charm.unit.status == ops.ActiveStatus()
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
cd content-cache && tox -e unit -- tests/unit/test_charm.py::test_certificate_available_writes_cert_and_reloads tests/unit/test_charm.py::test_certificate_removed_deletes_cert_and_sets_waiting tests/unit/test_charm.py::test_https_backends_without_ca_bundle_sets_waiting tests/unit/test_charm.py::test_http_backends_without_ca_bundle_stays_active -v
```

Expected: FAIL — `certificate-transfer` relation not found or `ca_certs` not imported in charm.

- [ ] **Step 4: Update charm.py**

Replace the imports and class body in `content-cache/src/charm.py` as follows.

Add to the imports section:

```python
import ca_certs
from charms.certificate_transfer_interface.v1.certificate_transfer import (
    CertificatesAvailableEvent,
    CertificatesRemovedEvent,
    CertificateTransferRequires,
)
```

Add a constant after the existing ones:

```python
CERTIFICATE_TRANSFER_INTEGRATION_NAME = "certificate-transfer"
WAIT_FOR_CA_CERT_MESSAGE = "Waiting for CA certificate via certificate-transfer"
```

In `__init__`, add after the COS agent line:

```python
        self._certificate_transfer = CertificateTransferRequires(
            self, CERTIFICATE_TRANSFER_INTEGRATION_NAME
        )
        framework.observe(
            self._certificate_transfer.on.certificate_set_updated,
            self._on_certificates_available,
        )
        framework.observe(
            self._certificate_transfer.on.certificates_removed,
            self._on_certificates_removed,
        )
```

Add new event handlers after `_on_cache_config_relation_broken`:

```python
    def _on_certificates_available(self, event: CertificatesAvailableEvent) -> None:
        """Handle certificate-transfer certificates available event."""
        ca_certs.write_ca_cert(event.relation_id, list(event.certificates))
        self._load_nginx_config()

    def _on_certificates_removed(self, event: CertificatesRemovedEvent) -> None:
        """Handle certificate-transfer certificates removed event."""
        ca_certs.remove_ca_cert(event.relation_id)
        self._load_nginx_config()
```

In `_load_nginx_config`, update the call to `nginx_manager.update_and_load_config` to pass the CA bundle path. First add the HTTPS check after `ported_config` is built:

```python
        ca_bundle_path = ca_certs.get_ca_bundle_path()
        any_https = any(
            str(config.backends[0].scheme) == "https"
            for _, config in nginx_config.items()
        )
        if any_https and ca_bundle_path is None:
            self.unit.status = ops.WaitingStatus(WAIT_FOR_CA_CERT_MESSAGE)
            self._clear_cache_backends()
            return
```

Then update the `update_and_load_config` call to pass `ca_bundle_path`:

```python
            nginx_manager.update_and_load_config(
                ported_config, self._get_instance_name(), ca_bundle_path=ca_bundle_path
            )
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd content-cache && tox -e unit,lint
```

Expected: all tests PASS, `lint: OK`

- [ ] **Step 6: Commit**

```bash
git add content-cache/src/charm.py content-cache/tests/unit/conftest.py content-cache/tests/unit/test_charm.py
git commit -m "feat: handle certificate_transfer events and WaitingStatus for HTTPS backends"
```

---

## Task 6: Replace placeholder integration tests in test_tls_cert.py

**Files:**
- Modify: `content-cache/tests/integration/test_tls_cert.py`
- Modify: `content-cache/tests/integration/conftest.py`
- Modify: `content-cache/tests/integration/helpers.py`

- [ ] **Step 1: Add a `cert_transfer_app_name` fixture to conftest.py**

In `content-cache/tests/integration/conftest.py`, add after the existing `cert_app_name` fixture:

```python
CERT_TRANSFER_CHARM_NAME = "self-signed-certificates"
CERTIFICATE_TRANSFER_INTEGRATION_NAME = "certificate-transfer"


@pytest.fixture(name="cert_transfer_app_name", scope="module")
def cert_transfer_app_name_fixture() -> str:
    """The application name for the certificate-transfer provider charm."""
    return "cert-transfer"
```

Note: `self-signed-certificates` charm supports both the `tls-certificates` and `certificate_transfer` interfaces.

- [ ] **Step 2: Add `cert_transfer_app` to the `deploy_applications_fixture`**

In `deploy_applications_fixture`, add `cert_transfer_app_name` parameter and deploy in parallel:

```python
    cert_transfer_app_deploy = model.deploy(
        CERT_TRANSFER_CHARM_NAME, cert_transfer_app_name, channel="latest/edge", base="ubuntu@22.04"
    )
```

Include it in the `asyncio.gather` call and the returned dict.

- [ ] **Step 3: Replace test_tls_cert.py**

Replace the entire content of `content-cache/tests/integration/test_tls_cert.py`:

```python
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests for HTTPS backend support via certificate_transfer."""

import pytest
import pytest_asyncio
from juju.application import Application
from juju.model import Model
from pytest_operator.plugin import OpsTest

from tests.integration.conftest import (
    CERTIFICATE_TRANSFER_INTEGRATION_NAME,
)
from tests.integration.helpers import CacheTester

CACHE_CONFIG_INTEGRATION_NAME = "cache-config"


@pytest_asyncio.fixture(name="https_cache_tester", scope="function")
async def https_cache_tester_fixture(
    model: Model,
    app: Application,
    config_app: Application,
    config_alt_app: Application,
) -> CacheTester:
    """Cache tester configured for HTTPS backends."""
    return CacheTester(model, app, config_app, config_alt_app)


async def test_https_backend_with_certificate_transfer(
    ops_test: OpsTest,
    model: Model,
    app: Application,
    cert_transfer_app: Application,
    https_cache_tester: CacheTester,
    http_ok_app: Application,
) -> None:
    """
    arrange: Content-cache with an HTTPS backend and a certificate-transfer provider.
    act: Integrate certificate-transfer and set HTTPS backend URL.
    assert: Content-cache reaches Active status and proxies the backend correctly.
    """
    await model.integrate(
        f"{cert_transfer_app.name}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
        f"{app.name}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
    )
    await model.wait_for_idle([app.name], status="waiting", timeout=5 * 60)

    backend_ip = await https_cache_tester._get_app_ip(http_ok_app)
    await https_cache_tester.integrate_config()
    await https_cache_tester.configure(
        backends=f"https://{backend_ip}:443",
        healthcheck_ssl_verify="false",
    )
    await model.wait_for_idle([app.name], status="active", timeout=10 * 60)

    cache_ip = await https_cache_tester._get_cache_ip()
    cache_port = await https_cache_tester._get_cache_port()
    response = await https_cache_tester.request(cache_ip, cache_port)
    assert response.status_code == 200


async def test_certificate_transfer_removal_clears_trust(
    ops_test: OpsTest,
    model: Model,
    app: Application,
    cert_transfer_app: Application,
    https_cache_tester: CacheTester,
    http_ok_app: Application,
) -> None:
    """
    arrange: Content-cache active with HTTPS backend and certificate-transfer integrated.
    act: Remove the certificate-transfer relation.
    assert: Content-cache moves to WaitingStatus (CA bundle cleared).
    """
    # Ensure we have an active HTTPS setup first
    await model.integrate(
        f"{cert_transfer_app.name}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
        f"{app.name}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
    )
    backend_ip = await https_cache_tester._get_app_ip(http_ok_app)
    await https_cache_tester.configure(backends=f"https://{backend_ip}:443")
    await model.wait_for_idle([app.name], status="active", timeout=10 * 60)

    # Remove certificate-transfer
    await model.remove_relation(
        f"{cert_transfer_app.name}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
        f"{app.name}:{CERTIFICATE_TRANSFER_INTEGRATION_NAME}",
    )
    await model.wait_for_idle([app.name], status="waiting", timeout=5 * 60)

    unit = app.units[0]
    assert "CA certificate" in unit.workload_status_message
```

- [ ] **Step 4: Commit**

```bash
git add content-cache/tests/integration/test_tls_cert.py content-cache/tests/integration/conftest.py
git commit -m "test(integration): replace placeholder TLS tests with HTTPS backend certificate_transfer tests"
```

---

## Task 7: Update documentation

**Files:**
- Modify: `docs/how-to/enable-https.md`
- Modify: `docs/explanation/charm-design.md`

- [ ] **Step 1: Update enable-https.md**

Replace the content of `docs/how-to/enable-https.md`:

```markdown
(how_to_enable_https)=

# How to connect to HTTPS backends

The Content Cache charm can proxy to backends over HTTPS by using HTTPS URLs in the `backends`
option on the `content-cache-backends-config` charm.

## Configure HTTPS backend URLs

```bash
juju config backends backends=https://10.10.1.1:443
```

When the URL scheme is `https`, nginx connects to the backend over TLS on the specified port.

## Provide a CA certificate via certificate_transfer

To verify the backend's TLS certificate, integrate a certificate provider charm (such as
`self-signed-certificates` or `lego`) using the `certificate-transfer` interface:

```bash
juju integrate <cert-provider>:certificate-transfer content-cache:certificate-transfer
```

Once the CA certificate is received, the content-cache charm will:

- Write the certificate to `/etc/nginx/certs/ca-bundle.pem`
- Configure nginx to verify backend certificates against this CA
- Use `proxy_ssl_verify on` and `proxy_ssl_server_name off` (SNI hostname validation is
  disabled in this version)

If HTTPS backends are configured but no CA certificate has been provided, the charm enters
`WaitingStatus` until the certificate-transfer relation is established.

Multiple certificate-transfer providers are supported; all provided CA certificates are merged
into a single bundle.

## TLS termination for incoming traffic

The Content Cache charm does not terminate TLS for incoming client requests.
Client-facing TLS termination is expected to be handled by an upstream ingress component,
such as `haproxy` configured with the `ingress-configurator` charm.
```

- [ ] **Step 2: Update charm-design.md**

In `docs/explanation/charm-design.md`, add a new section after the `## Cache-backends published address` section:

```markdown
## CA certificate trust for HTTPS backends

When using HTTPS backend URLs, the content-cache charm can receive the backend's CA
certificate via the `certificate-transfer` relation. The charm stores received certificates at
`/etc/nginx/certs/ca-<relation-id>.pem` and regenerates a merged bundle at
`/etc/nginx/certs/ca-bundle.pem` whenever the relation changes.

Nginx is configured with:

- `proxy_ssl_trusted_certificate /etc/nginx/certs/ca-bundle.pem` — trust the provided CA
- `proxy_ssl_verify on` — verify backend certificates against the CA
- `proxy_ssl_server_name off` — SNI hostname validation is disabled in this version

Multiple `certificate-transfer` providers are supported; all CA certificates are merged into
one bundle.

If HTTPS backends are configured but no CA certificate has been received, the charm enters
`WaitingStatus`. When the `certificate-transfer` relation is removed, the CA bundle is cleared
and the charm returns to `WaitingStatus` until a new CA is provided.

The `certificate-transfer` relation does not affect HTTP backends.
```

- [ ] **Step 3: Run RTD docs checks**

```bash
cd docs && make spelling && make linkcheck
```

Or trigger the RTD CI by pushing and checking the PR.

- [ ] **Step 4: Commit**

```bash
git add docs/how-to/enable-https.md docs/explanation/charm-design.md
git commit -m "docs: document certificate_transfer relation for HTTPS backend CA trust"
```

---

## Task 8: Final verification

- [ ] **Step 1: Run all unit tests and lint**

```bash
cd content-cache && tox -e unit,lint
```

Expected: all tests PASS, 10/10 pylint, `lint: OK`

- [ ] **Step 2: Run backends-config lint**

```bash
cd content-cache-backends-config && tox -e lint
```

Expected: `lint: OK`

- [ ] **Step 3: Push and create draft PR**

```bash
git push origin feat/support-https-isd-6137
gh pr create --draft --title "feat: support HTTPS backends via certificate_transfer relation (ISD-6137)" \
  --body "$(cat <<'EOF'
## Summary

- Adds `certificate-transfer` as a requirer relation to receive backend CA certificates
- Stores per-relation CA cert files at `/etc/nginx/certs/ca-<relation-id>.pem`; merges into a bundle at `/etc/nginx/certs/ca-bundle.pem`
- Configures nginx with `proxy_ssl_trusted_certificate`, `proxy_ssl_verify on`, `proxy_ssl_server_name off` for HTTPS backends
- Emits `WaitingStatus` when HTTPS backends are configured but no CA cert is available
- Replaces stale placeholder tests in `test_tls_cert.py` with real HTTPS backend integration tests

## Test Plan
- [ ] Unit tests: `tox -e unit` in `content-cache/`
- [ ] Lint: `tox -e lint` in `content-cache/`
- [ ] Integration tests triggered by CI
EOF
)" \
  --base feat/return-cache-backends-isd-6135 \
  --repo canonical/content-cache-operator
```

---

## Self-Review Notes

- All spec requirements covered: cert write ✓, cert remove ✓, bundle ✓, WaitingStatus ✓, `proxy_ssl_verify on` ✓, `proxy_ssl_server_name off` ✓, placeholder tests replaced ✓, docs updated ✓
- The `CertificatesAvailableEvent.certificates` attribute is a `set[str]` per the library; `list(event.certificates)` in `_on_certificates_available` is correct
- The `any_https` check uses `str(config.backends[0].scheme)` — pydantic `AnyHttpUrl.scheme` returns a `str` so the comparison is safe
- `patch_ca_certs` fixture is `autouse=True` so it applies to all charm tests automatically without changing existing tests
