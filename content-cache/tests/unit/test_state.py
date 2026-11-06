# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Test the charm state."""

from unittest.mock import MagicMock

import pytest

from charms.content_cache.v0.cache_config import CacheConfigRequirerAppData
from errors import ConfigurationError, IntegrationDataError
from state import (
    LocationConfig,
    _to_location_config,
    get_cache_backend_url,
    get_client_ip_hash_salt,
    get_nginx_config,
    is_client_ip_hash_salt_secret,
)

# Field-level validation (nginx time/size formats, backend-hostname-required-for-https,
# consistent backend schemes, status code ranges, etc.) is owned by the cache_config
# library itself (lib/charms/content_cache/v0/cache_config.py). The tests
# here only cover this charm's own responsibilities: reshaping the library's validated
# data into nginx_manager's rendering shape, and wiring get_nginx_config to the provider.

SAMPLE_APP_DATA = CacheConfigRequirerAppData(
    backends=["http://10.10.1.1:80", "http://10.10.2.2:80"],
    fail_timeout="30s",
    healthcheck_interval=2000,
    healthcheck_path="/",
    healthcheck_valid_status=[200],
    healthcheck_ssl_verify=False,
    proxy_cache_valid=["200 302 1h", "404 1m"],
)


def test_to_location_config_reshapes_requirer_data():
    """
    arrange: Validated cache-config requirer app data.
    act: Convert to LocationConfig.
    assert: The nginx-rendering shape has the equivalent, correctly-typed fields.
    """
    config = _to_location_config(SAMPLE_APP_DATA)

    assert isinstance(config, LocationConfig)
    assert len(config.backends) == 2
    assert config.backends[0].host == "10.10.1.1"
    assert config.backends[0].scheme == "http"
    assert config.backends[1].host == "10.10.2.2"
    assert config.fail_timeout == "30s"
    assert config.proxy_cache_valid == ("200 302 1h", "404 1m")
    assert config.healthcheck_config.ssl_verify is False
    assert config.healthcheck_config.path == "/"
    assert config.healthcheck_config.interval == 2000


def test_to_location_config_defaults():
    """
    arrange: Requirer app data relying on backend_hostname/cache_inactive/cache_max_size
        defaults.
    act: Convert to LocationConfig.
    assert: Defaults are carried over correctly.
    """
    config = _to_location_config(SAMPLE_APP_DATA)

    assert config.backend_hostname == ""
    assert config.cache_inactive == "10m"
    assert config.cache_max_size == ""


def test_get_nginx_config_returns_per_relation_dict():
    """
    arrange: A fake CacheConfigProvider returning data for one relation.
    act: Call get_nginx_config.
    assert: Returns a dict keyed by relation id with the reshaped LocationConfig.
    """
    provider = MagicMock()
    provider.get_requirers_data.return_value = {7: SAMPLE_APP_DATA}

    config = get_nginx_config(provider)

    assert set(config) == {7}
    assert isinstance(config[7], LocationConfig)
    assert config[7].backends[0].host == "10.10.1.1"


def test_get_nginx_config_empty_when_no_requirers():
    """
    arrange: A fake CacheConfigProvider with no requirer data.
    act: Call get_nginx_config.
    assert: Returns an empty dict.
    """
    provider = MagicMock()
    provider.get_requirers_data.return_value = {}

    assert get_nginx_config(provider) == {}


def test_get_nginx_config_wraps_library_error():
    """
    arrange: A fake CacheConfigProvider whose get_requirers_data raises the library's error.
    act: Call get_nginx_config.
    assert: The charm's own IntegrationDataError is raised instead, so callers only need to
        catch content-cache's error types.
    """
    from charms.content_cache.v0.cache_config import CacheConfigIntegrationDataError

    provider = MagicMock()
    provider.get_requirers_data.side_effect = CacheConfigIntegrationDataError("bad data")

    with pytest.raises(IntegrationDataError, match="bad data"):
        get_nginx_config(provider)


def test_get_cache_backend_url_uses_https_when_has_cache_cert():
    """
    arrange: A mock charm with a bind address and has_cache_cert=True.
    act: Call get_cache_backend_url.
    assert: Returns an https:// URL.
    """
    charm = MagicMock()
    charm.model.get_binding.return_value.network.bind_address = "10.0.0.1"
    relation = MagicMock()

    result = get_cache_backend_url(charm, relation, 30000, has_cache_cert=True)

    assert result.startswith("https://")


def test_get_cache_backend_url_uses_http_by_default():
    """
    arrange: A mock charm with a bind address and has_cache_cert=False (default).
    act: Call get_cache_backend_url.
    assert: Returns an http:// URL.
    """
    charm = MagicMock()
    charm.model.get_binding.return_value.network.bind_address = "10.0.0.1"
    relation = MagicMock()

    result = get_cache_backend_url(charm, relation, 30000)

    assert result.startswith("http://")


def test_get_cache_backend_url_http():
    """
    arrange: A mock charm with a bind address and a relation.
    act: Call get_cache_backend_url with port 8080.
    assert: Returns an http URL containing the bind IP and port.
    """
    charm = MagicMock()
    rel = MagicMock()
    charm.model.get_binding.return_value.network.bind_address = "10.1.2.3"
    port = 8080

    result = get_cache_backend_url(charm, rel, port)

    assert result == "http://10.1.2.3:8080"
    charm.model.get_binding.assert_called_once_with(rel)


def _charm_with_config(config: dict) -> MagicMock:
    """Build a mock charm exposing the given .config dict."""
    charm = MagicMock()
    charm.config = config
    return charm


def test_get_client_ip_hash_salt_returns_none_when_not_configured():
    """
    arrange: A mock charm with no client-ip-hash-salt config.
    act: Call get_client_ip_hash_salt.
    assert: Returns None.
    """
    charm = _charm_with_config({})

    assert get_client_ip_hash_salt(charm) is None


def test_get_client_ip_hash_salt_rejects_blank_secret_uri():
    """
    arrange: A mock charm whose client-ip-hash-salt config is set to a whitespace-only
        value, rather than being genuinely unset (None).
    act: Call get_client_ip_hash_salt.
    assert: ConfigurationError is raised instead of silently disabling hashing.
    """
    charm = _charm_with_config({"client-ip-hash-salt": "   "})

    with pytest.raises(ConfigurationError, match="must reference a valid secret URI"):
        get_client_ip_hash_salt(charm)


def test_get_client_ip_hash_salt_returns_salt_when_valid():
    """
    arrange: A mock charm with a client-ip-hash-salt config pointing at a valid secret.
    act: Call get_client_ip_hash_salt.
    assert: Returns the salt value.
    """
    charm = _charm_with_config({"client-ip-hash-salt": "secret:abc123"})
    charm.model.get_secret.return_value.get_content.return_value = {"salt": "s3cr3t-salt"}

    assert get_client_ip_hash_salt(charm) == "s3cr3t-salt"
    charm.model.get_secret.assert_called_once_with(id="secret:abc123")


def test_get_client_ip_hash_salt_rejects_inaccessible_secret():
    """
    arrange: A mock charm whose secret is not accessible.
    act: Call get_client_ip_hash_salt.
    assert: ConfigurationError is raised.
    """
    import ops

    charm = _charm_with_config({"client-ip-hash-salt": "secret:missing"})
    charm.model.get_secret.side_effect = ops.SecretNotFoundError()

    with pytest.raises(ConfigurationError, match="does not exist or cannot be accessed"):
        get_client_ip_hash_salt(charm)


@pytest.mark.parametrize(
    "secret_content",
    [
        pytest.param({"other": "value"}, id="missing_key"),
        pytest.param({"salt": ""}, id="empty"),
        pytest.param({"salt": "   "}, id="whitespace"),
    ],
)
def test_get_client_ip_hash_salt_rejects_blank_value(secret_content: dict):
    """
    arrange: A mock charm whose secret has no usable 'salt' value.
    act: Call get_client_ip_hash_salt.
    assert: ConfigurationError is raised.
    """
    charm = _charm_with_config({"client-ip-hash-salt": "secret:abc123"})
    charm.model.get_secret.return_value.get_content.return_value = secret_content

    with pytest.raises(ConfigurationError, match="non-empty 'salt' value"):
        get_client_ip_hash_salt(charm)


@pytest.mark.parametrize(
    "salt",
    [
        pytest.param('unsafe"salt', id="quote"),
        pytest.param("unsafe\\salt", id="backslash"),
        pytest.param("unsafe\nsalt", id="control_character"),
        pytest.param("unsafe$salt", id="dollar_sign"),
    ],
)
def test_get_client_ip_hash_salt_rejects_unsafe_value(salt: str):
    """
    arrange: A mock charm whose secret contains a disallowed character.
    act: Call get_client_ip_hash_salt.
    assert: ConfigurationError is raised.
    """
    charm = _charm_with_config({"client-ip-hash-salt": "secret:abc123"})
    charm.model.get_secret.return_value.get_content.return_value = {"salt": salt}

    with pytest.raises(ConfigurationError, match="must not contain control characters"):
        get_client_ip_hash_salt(charm)


def test_is_client_ip_hash_salt_secret_matches_configured_secret():
    """
    arrange: A mock charm with client-ip-hash-salt configured to a specific secret.
    act: Call is_client_ip_hash_salt_secret with that secret's id.
    assert: Returns True.
    """
    charm = _charm_with_config({"client-ip-hash-salt": "secret:abc123"})
    charm.model.get_secret.return_value.id = "secret:abc123"

    assert is_client_ip_hash_salt_secret(charm, "secret:abc123") is True


def test_is_client_ip_hash_salt_secret_rejects_other_secret():
    """
    arrange: A mock charm with client-ip-hash-salt configured to a specific secret.
    act: Call is_client_ip_hash_salt_secret with a different secret's id.
    assert: Returns False.
    """
    charm = _charm_with_config({"client-ip-hash-salt": "secret:abc123"})
    charm.model.get_secret.return_value.id = "secret:abc123"

    assert is_client_ip_hash_salt_secret(charm, "secret:unrelated") is False


def test_is_client_ip_hash_salt_secret_false_when_not_configured():
    """
    arrange: A mock charm with no client-ip-hash-salt config.
    act: Call is_client_ip_hash_salt_secret with any secret id.
    assert: Returns False, without attempting to resolve a secret.
    """
    charm = _charm_with_config({})

    assert is_client_ip_hash_salt_secret(charm, "secret:abc123") is False
    charm.model.get_secret.assert_not_called()


def test_is_client_ip_hash_salt_secret_false_when_configured_secret_inaccessible():
    """
    arrange: A mock charm whose configured client-ip-hash-salt secret cannot be resolved.
    act: Call is_client_ip_hash_salt_secret.
    assert: Returns False instead of raising.
    """
    import ops

    charm = _charm_with_config({"client-ip-hash-salt": "secret:missing"})
    charm.model.get_secret.side_effect = ops.SecretNotFoundError()

    assert is_client_ip_hash_salt_secret(charm, "secret:missing") is False
