# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Test the charm state."""

import json
from unittest.mock import MagicMock

import pytest

from errors import ConfigurationError
from state import (
    BACKENDS_FIELD_NAME,
    PROXY_CACHE_VALID_FIELD_NAME,
    LocationConfig,
    get_cache_backend_url,
)
from tests.unit.conftest import SAMPLE_INTEGRATION_DATA


def test_config_from_integration_data():
    """
    arrange: Valid sample integration data with URL-format backends.
    act: Create the config from the data.
    assert: The configurations are correctly parsed.
    """
    config = LocationConfig.from_integration_data(SAMPLE_INTEGRATION_DATA)

    assert len(config.backends) == 2
    assert config.backends[0].host == "10.10.1.1"
    assert config.backends[0].scheme == "http"
    assert config.backends[1].host == "10.10.2.2"
    assert config.fail_timeout == "30s"
    assert config.proxy_cache_valid == ("200 302 1h", "404 1m")
    assert config.healthcheck_config.ssl_verify is False


@pytest.mark.parametrize(
    "invalid_backends, error_message",
    [
        pytest.param("[]", "backends config cannot be empty.", id="empty backends"),
        pytest.param(
            "value", "Unable to parse backends config as json: value", id="none json value"
        ),
        pytest.param(
            '{"value": 1}',
            'Unable to convert backends config to list: {"value": 1}',
            id="incorrect backends format",
        ),
        pytest.param(
            '["10.10.1.1"]',
            "Config error: ['backends = 10.10.1.1:",
            id="bare IP rejected",
        ),
    ],
)
def test_config_with_invalid_backends_integration_data(invalid_backends, error_message):
    """
    arrange: Sample integration data with invalid backends.
    act: Create the config from the data.
    assert: Exception raised with the correct error message.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[BACKENDS_FIELD_NAME] = invalid_backends

    with pytest.raises(ConfigurationError) as err:
        LocationConfig.from_integration_data(data)

    assert error_message in str(err.value)


def test_config_https_backends_integration_data():
    """
    arrange: Valid sample integration data with https URL backends and required HTTPS fields.
    act: Create the config from the data.
    assert: The configurations are correctly parsed with https scheme.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[BACKENDS_FIELD_NAME] = '["https://10.10.1.1:443", "https://10.10.2.2:443"]'
    data["backend_hostname"] = "test.example.com"
    config = LocationConfig.from_integration_data(data)

    assert len(config.backends) == 2
    assert config.backends[0].scheme == "https"
    assert config.backends[1].scheme == "https"


def test_config_https_backends_require_backend_fields():
    """
    arrange: HTTPS integration data without backend-hostname.
    act: Create the config from the data.
    assert: ConfigurationError is raised.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[BACKENDS_FIELD_NAME] = '["https://10.10.1.1:443"]'

    with pytest.raises(ConfigurationError) as err:
        LocationConfig.from_integration_data(data)

    assert "backend-hostname is required" in str(err.value)


def test_config_mixed_scheme_raises():
    """
    arrange: Integration data with backends of mixed http/https schemes.
    act: Create the config from the data.
    assert: ConfigurationError is raised.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[BACKENDS_FIELD_NAME] = '["http://10.10.1.1:80", "https://10.10.2.2:443"]'

    with pytest.raises(ConfigurationError) as err:
        LocationConfig.from_integration_data(data)

    assert "mixed" in str(err.value).lower() or "scheme" in str(err.value).lower()


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


@pytest.mark.parametrize(
    "invalid_proxy_cache_valid, error_message",
    [
        pytest.param(
            "invalid",
            "Unable to parse proxy_cache_valid config as json: invalid",
            id="invalid format",
        ),
        pytest.param(
            '["200"]',
            "The proxy_cache_valid requires at least one status code and a time: 200",
            id="no time",
        ),
        pytest.param(
            '{"hello": 10}',
            'Unable to convert proxy_cache_valid config to list: {"hello": 10}',
            id="non list",
        ),
        pytest.param(
            '["200 302 1y"]',
            "Invalid time unit for proxy_cache_valid: 1y",
            id="Invalid time unit",
        ),
        pytest.param(
            '["200 tenm"]',
            "Non-int time in proxy_cache_valid: tenm",
            id="non-int time",
        ),
        pytest.param(
            '["200 -10h"]',
            "Time must be positive int for proxy_cache_valid: -10h",
            id="negative time",
        ),
        pytest.param(
            '["ok 30m"]',
            "Non-int status code in proxy_cache_valid: ok",
            id="non-int status code",
        ),
        pytest.param(
            '["200 99 30m"]',
            "Invalid status code in proxy_cache_valid: 99",
            id="invalid status code",
        ),
    ],
)
def test_config_invalid_proxy_cache_valid_integration_data(
    invalid_proxy_cache_valid: str, error_message: str
):
    """
    arrange: Sample integration data with invalid proxy_cache_valid.
    act: Create the config from the data.
    assert: Exception raised with the correct error message.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[PROXY_CACHE_VALID_FIELD_NAME] = invalid_proxy_cache_valid

    with pytest.raises(ConfigurationError) as err:
        LocationConfig.from_integration_data(data)

    assert error_message in str(err.value)


@pytest.mark.parametrize(
    "proxy_cache_valid",
    [
        pytest.param("[]", id="empty"),
        pytest.param(
            '["200 302 2h", "400 1m"]',
            id="common",
        ),
        pytest.param('["200 1m"]', id="single item"),
        pytest.param('["200 1s"]', id="seconds in time"),
        pytest.param('["200 1h"]', id="hours in time"),
        pytest.param('["100 200 302 404 1h"]', id="long item"),
        pytest.param(
            '["100 200 302 404 1h", "300 500 502 2m", "202 201 401 402 403 1s"]',
            id="multiple long in proxy-cache-valid",
        ),
    ],
)
def test_config_valid_proxy_cache_valid_integration_data(proxy_cache_valid: str):
    """
    arrange: Sample integration data with valid proxy_cache_valid.
    act: Create the config from the data.
    assert: Configuration parsed correctly with expected proxy_cache_valid.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[PROXY_CACHE_VALID_FIELD_NAME] = proxy_cache_valid

    config = LocationConfig.from_integration_data(data)

    assert len(config.backends) == 2
    assert config.fail_timeout == "30s"
    assert config.healthcheck_config.path == "/"
    assert config.healthcheck_config.interval == 2000
    assert config.proxy_cache_valid == tuple(json.loads(proxy_cache_valid))
