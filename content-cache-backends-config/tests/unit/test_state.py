# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the state.py"""

import json
from ipaddress import IPv4Address

import pydantic_core
import pytest
from factories import MockCharmFactory  # pylint: disable=import-error

from errors import ConfigurationError
from src.state import (
    BACKENDS_CONFIG_NAME,
    BACKENDS_PATH_CONFIG_NAME,
    HOSTNAME_CONFIG_NAME,
    PATH_CONFIG_NAME,
    PROTOCOL_CONFIG_NAME,
    PROXY_CACHE_VALID_CONFIG_NAME,
    Configuration,
)


def mock_error_model_dump_json(_):
    """Mock error in model_dump_json of pydantic.BaseModel.

    Raises:
        PydanticSerializationError: Mock error.
    """
    raise pydantic_core.PydanticSerializationError("mock error")


def mock_error_json_dumps(_):
    """Mock error in json.dumps.

    Raises:
        ValueError: Mock error.
    """
    raise ValueError("mock error")


def test_valid_config():
    """
    arrange: Mock charm with valid configurations.
    act: Create the configuration from the charm.
    assert: Correct configurations from the mock charm.
    """
    charm = MockCharmFactory()

    config = Configuration.from_charm(charm)

    assert config.hostname == "example.com"
    assert config.path == "/"
    assert config.backends == (IPv4Address("10.10.1.1"), IPv4Address("10.10.2.2"))
    assert config.protocol == "https"
    assert config.fail_timeout == "30s"
    assert config.backends_path == "/"
    assert config.proxy_cache_valid == ()


def test_hostname_with_subdomain():
    """
    arrange: Mock charm with valid configurations.
    act: Use a domain with subdomain as hostname, and create the configuration from the charm.
    assert: Correct configurations from the mock charm.
    """
    charm = MockCharmFactory()
    charm.config[HOSTNAME_CONFIG_NAME] = "sub.example.com"

    config = Configuration.from_charm(charm)

    assert config.hostname == "sub.example.com"
    assert config.path == "/"
    assert config.backends == (IPv4Address("10.10.1.1"), IPv4Address("10.10.2.2"))
    assert config.protocol == "https"
    assert config.fail_timeout == "30s"
    assert config.backends_path == "/"
    assert config.proxy_cache_valid == ()


def test_empty_hostname():
    """
    arrange: Mock charm with empty hostname.
    act: Create the configuration from the charm.
    assert: Correct configurations from the mock charm.
    """
    charm = MockCharmFactory()
    charm.config[HOSTNAME_CONFIG_NAME] = "   "

    with pytest.raises(ConfigurationError) as err:
        Configuration.from_charm(charm)
    assert (
        str(err.value) == "Config error: ['hostname = : String should have at least 1 character']"
    )


def test_long_hostname():
    """
    arrange: Mock charm with long hostname.
    act: Create the configuration from the charm.
    assert: Correct configurations from the mock charm.
    """
    charm = MockCharmFactory()
    charm.config[HOSTNAME_CONFIG_NAME] = "a" * 256

    with pytest.raises(ConfigurationError) as err:
        Configuration.from_charm(charm)

    assert "Value error, Hostname cannot be longer than 255" in str(err.value)


def test_invalid_hostname():
    """
    arrange: Mock charm with hostname with invalid character.
    act: Create the configuration from the charm.
    assert: Correct configurations from the mock charm.
    """
    charm = MockCharmFactory()
    charm.config[HOSTNAME_CONFIG_NAME] = "example?.com"

    with pytest.raises(ConfigurationError) as err:
        Configuration.from_charm(charm)

    assert "consist of alphanumeric and hyphen" in str(err.value)


def test_longer_path():
    """
    arrange: Mock charm with valid configurations.
    act: Use a longer path, and create the configuration from the charm.
    assert: Correct configurations from the mock charm.
    """
    charm = MockCharmFactory()
    charm.config[PATH_CONFIG_NAME] = "/path/to/destination/0"
    charm.config[BACKENDS_PATH_CONFIG_NAME] = "/path/to/destination/2"

    config = Configuration.from_charm(charm)

    assert config.hostname == "example.com"
    assert config.path == "/path/to/destination/0"
    assert config.backends == (IPv4Address("10.10.1.1"), IPv4Address("10.10.2.2"))
    assert config.protocol == "https"
    assert config.fail_timeout == "30s"
    assert config.backends_path == "/path/to/destination/2"
    assert config.proxy_cache_valid == ()


def test_empty_path():
    """
    arrange: Mock charm with empty path.
    act: Create the configuration from the charm.
    assert: Correct configurations from the mock charm.
    """
    charm = MockCharmFactory()
    charm.config[PATH_CONFIG_NAME] = "   "

    with pytest.raises(ConfigurationError) as err:
        Configuration.from_charm(charm)

    assert str(err.value) == "Config error: ['path = : String should have at least 1 character']"


def test_invalid_path():
    """
    arrange: Mock charm with path with invalid character.
    act: Create the configuration from the charm.
    assert: Correct configurations from the mock charm.
    """
    charm = MockCharmFactory()
    charm.config[PATH_CONFIG_NAME] = "/^"

    with pytest.raises(ConfigurationError) as err:
        Configuration.from_charm(charm)

    assert (
        str(err.value)
        == "Config error: ['path = /^: Value error, Path contains non-allowed character']"
    )


def test_invalid_backends_path():
    """
    arrange: Mock charm with path with invalid character.
    act: Create the configuration from the charm.
    assert: Correct configurations from the mock charm.
    """
    charm = MockCharmFactory()
    charm.config[BACKENDS_PATH_CONFIG_NAME] = "/path/{"

    with pytest.raises(ConfigurationError) as err:
        Configuration.from_charm(charm)

    assert "backends_path = /path/{: Value error, Path contains non-allowed character" in str(
        err.value
    )


@pytest.mark.parametrize(
    "invalid_backends, error_message",
    [
        pytest.param("", "Empty backends configuration found", id="empty"),
        pytest.param(
            "mock",
            "Config error: ['backends = mock: value is not a valid IPv4 or IPv6 address']",
            id="incorrect format",
        ),
        pytest.param(
            "10.10.1",
            "Config error: ['backends = 10.10.1: value is not a valid IPv4 or IPv6 address']",
            id="incorrect IP format",
        ),
    ],
)
def test_config_backends_invalid_backends(invalid_backends: str, error_message: str):
    """
    arrange: Mock charm with invalid backends config.
    act: Create the state from the charm.
    assert: Configuration error raised with a correct error message.
    """
    charm = MockCharmFactory()
    charm.config[BACKENDS_CONFIG_NAME] = invalid_backends

    with pytest.raises(ConfigurationError) as err:
        Configuration.from_charm(charm)

    assert str(err.value) == error_message


def test_http_protocol():
    """
    arrange: Mock charm with valid configurations.
    act: Use a http as protocol, and create the configuration from the charm.
    assert: Correct configurations from the mock charm.
    """
    charm = MockCharmFactory()
    charm.config[PROTOCOL_CONFIG_NAME] = "http"

    config = Configuration.from_charm(charm)

    assert config.hostname == "example.com"
    assert config.path == "/"
    assert config.backends == (IPv4Address("10.10.1.1"), IPv4Address("10.10.2.2"))
    assert config.protocol == "http"
    assert config.fail_timeout == "30s"
    assert config.backends_path == "/"
    assert config.proxy_cache_valid == ()


def test_config_protocol_invalid():
    """
    arrange: Mock charm with invalid protocol config.
    act: Create the state from the charm.
    assert: Configuration error raised with a correct error message.
    """
    charm = MockCharmFactory()
    charm.config[PROTOCOL_CONFIG_NAME] = "unknown"

    with pytest.raises(ConfigurationError) as err:
        Configuration.from_charm(charm)

    assert (
        str(err.value)
        == "Config error: [\"protocol = unknown: Input should be 'http' or 'https'\"]"
    )


def test_invalid_format_proxy_cache_valid():
    """
    arrange: Mock charm with invalid cache valid config.
    act: Create the state from the charm.
    assert: Configuration error raised with a correct error message.
    """
    charm = MockCharmFactory()
    charm.config[PROXY_CACHE_VALID_CONFIG_NAME] = "invalid"

    with pytest.raises(ConfigurationError) as err:
        Configuration.from_charm(charm)

    assert "Unable to parse proxy_cache_valid: invalid" in str(err.value)


@pytest.mark.parametrize(
    "invalid_proxy_cache_valid, error_message",
    [
        pytest.param(
            "invalid",
            "Unable to parse proxy_cache_valid: invalid",
            id="invalid format",
        ),
        pytest.param(
            '["200"]',
            "Invalid item in proxy_cache_valid: 200",
            id="no time",
        ),
        pytest.param(
            '{"hello": 10}',
            'The proxy_cache_valid is not a list: {"hello": 10}',
            id="non list",
        ),
        pytest.param(
            '["200 302 1y"]',
            "Invalid time for proxy_cache_valid: 1y",
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
def test_invalid_proxy_cache_valid(invalid_proxy_cache_valid: str, error_message: str):
    """
    arrange: Mock charm with various invalid cache valid configurations.
    act: Create the state from the charm.
    assert: Configuration error raised with a correct error message.
    """
    charm = MockCharmFactory()
    charm.config[PROXY_CACHE_VALID_CONFIG_NAME] = invalid_proxy_cache_valid

    with pytest.raises(ConfigurationError) as err:
        Configuration.from_charm(charm)

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
def test_valid_proxy_cache_valid(proxy_cache_valid: str):
    """
    arrange: Mock charm with valid proxy_cache_valid configuration.
    act: Create the configuration from the charm.
    assert: Correct configurations from the mock charm.
    """
    charm = MockCharmFactory()
    charm.config[PROXY_CACHE_VALID_CONFIG_NAME] = proxy_cache_valid

    config = Configuration.from_charm(charm)

    assert config.hostname == "example.com"
    assert config.path == "/"
    assert config.backends == (IPv4Address("10.10.1.1"), IPv4Address("10.10.2.2"))
    assert config.protocol == "https"
    assert config.fail_timeout == "30s"
    assert config.backends_path == "/"
    assert config.proxy_cache_valid == tuple(json.loads(proxy_cache_valid))


def test_configuration_to_data():
    """
    arrange: Mock charm with valid configurations.
    act: Create the configuration from the charm, and convert to dict.
    assert: Data contains the configurations.
    """
    charm = MockCharmFactory()

    config = Configuration.from_charm(charm)
    data = config.to_integration_data()

    assert data == {
        "hostname": "example.com",
        "path": "/",
        "backends": '["10.10.1.1", "10.10.2.2"]',
        "protocol": "https",
        "fail_timeout": "30s",
        "backends_path": "/",
        "proxy_cache_valid": "[]",
    }


def test_configuration_to_data_model_dump_error(monkeypatch):
    """
    arrange: Mock model_dump_json to raise error.
    act: Create the configuration from the charm, and convert to dict.
    assert: Error raised with the correct error message.
    """
    monkeypatch.setattr("state.pydantic.BaseModel.model_dump_json", mock_error_model_dump_json)
    charm = MockCharmFactory()

    config = Configuration.from_charm(charm)

    with pytest.raises(ConfigurationError) as err:
        config.to_integration_data()

    assert "Unable to convert configuration to integration data format" in str(err.value)


def test_configuration_to_json_dumps_error(monkeypatch):
    """
    arrange: Mock json.dumps to raise error.
    act: Create the configuration from the charm, and convert to dict.
    assert: Error raised with the correct error message.
    """
    monkeypatch.setattr("state.json.dumps", mock_error_json_dumps)
    charm = MockCharmFactory()

    config = Configuration.from_charm(charm)

    with pytest.raises(ConfigurationError) as err:
        config.to_integration_data()

    assert "Unable to convert configuration to integration data format" in str(err.value)
