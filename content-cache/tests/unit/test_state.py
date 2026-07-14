# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Test the charm state."""

import json
from ipaddress import IPv4Address

import pytest

from errors import ConfigurationError
from state import (
    BACKENDS_FIELD_NAME,
    FAIL_TIMEOUT_FIELD_NAME,
    HEALTHCHECK_INTERVAL_FIELD_NAME,
    HEALTHCHECK_PATH_FIELD_NAME,
    HEALTHCHECK_SSL_VERIFY_FIELD_NAME,
    HEALTHCHECK_VALID_STATUS_FIELD_NAME,
    PROTOCOL_FIELD_NAME,
    PROXY_CACHE_VALID_FIELD_NAME,
    LocationConfig,
)
from tests.unit.conftest import SAMPLE_INTEGRATION_DATA


def test_config_from_integration_data():
    """
    arrange: Valid sample integration data.
    act: Create the config from the data.
    assert: The configurations are correctly parsed.
    """
    config = LocationConfig.from_integration_data(SAMPLE_INTEGRATION_DATA)

    assert config.backends == (IPv4Address("10.10.1.1"), IPv4Address("10.10.2.2"))
    assert config.protocol.value == "https"
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
            '["10.10.1"]',
            "Config error: ['backends = 10.10.1: value is not a valid IPv4 or IPv6 address']",
            id="incorrect IP format",
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

    assert str(err.value) == error_message


def test_config_http_protocol_integration_data():
    """
    arrange: Valid sample integration data with http as protocol.
    act: Create the config from the data.
    assert: The configurations are correctly parsed.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[PROTOCOL_FIELD_NAME] = "http"
    config = LocationConfig.from_integration_data(data)

    assert config.backends == (IPv4Address("10.10.1.1"), IPv4Address("10.10.2.2"))
    assert config.protocol.value == "http"
    assert config.fail_timeout == "30s"
    assert config.proxy_cache_valid == ("200 302 1h", "404 1m")


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
    assert: Exception raised with the correct error message.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[PROXY_CACHE_VALID_FIELD_NAME] = proxy_cache_valid

    config = LocationConfig.from_integration_data(data)

    assert config.backends == (IPv4Address("10.10.1.1"), IPv4Address("10.10.2.2"))
    assert config.protocol.value == "https"
    assert config.fail_timeout == "30s"
    assert config.healthcheck_config.path == "/"
    assert config.healthcheck_config.interval == 2000
    assert config.proxy_cache_valid == tuple(json.loads(proxy_cache_valid))


# ============================
# Story 1 TDD: New behavior tests (should FAIL until production code is updated)
# ============================

MINIMAL_INTEGRATION_DATA = {
    BACKENDS_FIELD_NAME: '["10.10.1.1"]',
    PROTOCOL_FIELD_NAME: "https",
    FAIL_TIMEOUT_FIELD_NAME: "30s",
    HEALTHCHECK_INTERVAL_FIELD_NAME: "2000",
    HEALTHCHECK_PATH_FIELD_NAME: "/",
    HEALTHCHECK_SSL_VERIFY_FIELD_NAME: "false",
    HEALTHCHECK_VALID_STATUS_FIELD_NAME: "[200]",
    PROXY_CACHE_VALID_FIELD_NAME: "[]",
}


def test_location_config_has_no_hostname_field():
    """
    arrange: Minimal integration data without hostname.
    act: Create LocationConfig from data.
    assert: LocationConfig has no hostname field.
    """
    config = LocationConfig.from_integration_data(MINIMAL_INTEGRATION_DATA)

    assert not hasattr(config, "hostname")


def test_location_config_has_no_path_field():
    """
    arrange: Minimal integration data without path.
    act: Create LocationConfig from data.
    assert: LocationConfig has no path field.
    """
    config = LocationConfig.from_integration_data(MINIMAL_INTEGRATION_DATA)

    assert not hasattr(config, "path")


def test_location_config_has_no_backends_path_field():
    """
    arrange: Minimal integration data without backends_path.
    act: Create LocationConfig from data.
    assert: LocationConfig has no backends_path field.
    """
    config = LocationConfig.from_integration_data(MINIMAL_INTEGRATION_DATA)

    assert not hasattr(config, "backends_path")


def test_location_config_parses_required_fields_without_routing():
    """
    arrange: Integration data without any routing fields (hostname, path, backends_path).
    act: Create LocationConfig from data.
    assert: Config parsed correctly with backends, protocol, fail_timeout.
    """
    config = LocationConfig.from_integration_data(MINIMAL_INTEGRATION_DATA)

    assert config.backends == (IPv4Address("10.10.1.1"),)
    assert config.protocol.value == "https"
    assert config.fail_timeout == "30s"
