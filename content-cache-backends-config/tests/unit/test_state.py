# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the state.py"""

import json

import pydantic_core
import pytest
from factories import MockCharmFactory  # pylint: disable=import-error

from errors import ConfigurationError
from src.state import (
    BACKENDS_CONFIG_NAME,
    HEALTHCHECK_INTERVAL_CONFIG_NAME,
    HEALTHCHECK_PATH_CONFIG_NAME,
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
    arrange: Mock charm with valid URL-format backends configuration.
    act: Create the configuration from the charm.
    assert: Correct configurations parsed from the mock charm.
    """
    charm = MockCharmFactory()

    config = Configuration.from_charm(charm)

    assert len(config.backends) == 2
    assert config.backends[0].host == "10.10.1.1"
    assert config.backends[0].scheme == "http"
    assert config.backends[1].host == "10.10.2.2"
    assert config.fail_timeout == "30s"
    assert config.healthcheck.path == "/healthz"
    assert config.healthcheck.interval == 2123
    assert config.proxy_cache_valid == ()


def test_https_backends():
    """
    arrange: Mock charm with https URL-format backends configuration.
    act: Create the configuration from the charm.
    assert: Backends parsed with https scheme.
    """
    charm = MockCharmFactory()
    charm.config[BACKENDS_CONFIG_NAME] = "https://10.10.1.1:443,https://10.10.2.2:443"

    config = Configuration.from_charm(charm)

    assert len(config.backends) == 2
    assert config.backends[0].scheme == "https"
    assert config.backends[1].scheme == "https"


@pytest.mark.parametrize(
    "invalid_backends, error_message",
    [
        pytest.param("", "Empty backends configuration found", id="empty"),
        pytest.param(
            "10.10.1.1",
            "Config error: ['backends = 10.10.1.1:",
            id="bare IP rejected",
        ),
        pytest.param(
            "ftp://10.10.1.1",
            'Config error: ["backends = ftp://10.10.1.1:',
            id="wrong scheme rejected",
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

    assert error_message in str(err.value)


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

    assert len(config.backends) == 2
    assert config.fail_timeout == "30s"
    assert config.proxy_cache_valid == tuple(json.loads(proxy_cache_valid))


def test_configuration_to_data():
    """
    arrange: Mock charm with valid URL-format backends.
    act: Create the configuration from the charm, and convert to dict.
    assert: Data contains backends as JSON URL list without protocol field.
    """
    charm = MockCharmFactory()

    config = Configuration.from_charm(charm)
    data = config.to_integration_data()

    backends = json.loads(data["backends"])
    assert len(backends) == 2
    assert "10.10.1.1" in backends[0]
    assert "10.10.2.2" in backends[1]
    assert all(b.startswith("http://") for b in backends)
    assert "protocol" not in data
    assert data["fail_timeout"] == "30s"
    assert data["healthcheck_interval"] == "2123"
    assert data["healthcheck_path"] == "/healthz"
    assert data["healthcheck_ssl_verify"] == "false"
    assert data["healthcheck_valid_status"] == "[200]"
    assert data["proxy_cache_valid"] == "[]"


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


@pytest.mark.parametrize(
    "bad_value,error_msg",
    [
        ("  ", "String should have at least 1 character"),
        ("{", "Value error, Path contains non-allowed character"),
    ],
    ids=["empty", "bad_character"],
)
def test_invalid_healthcheck_path(bad_value, error_msg):
    """
    arrange: Mock charm with invalid healthcheck path.
    act: Create the configuration from the charm.
    assert: Configuration error is raised.
    """
    charm = MockCharmFactory()
    charm.config[HEALTHCHECK_PATH_CONFIG_NAME] = bad_value

    with pytest.raises(ConfigurationError) as err:
        Configuration.from_charm(charm)

    assert str(err.value) == f"Config error: ['path = {bad_value.strip()}: {error_msg}']"


@pytest.mark.parametrize(
    "bad_value,error_msg",
    [
        ("  ", "Input should be a valid integer, unable to parse string as an integer"),
        ("-1", "Input should be greater than 0"),
        ("0", "Input should be greater than 0"),
    ],
    ids=["empty", "negative", "zero"],
)
def test_invalid_healthcheck_interval(bad_value, error_msg):
    """
    arrange: Mock charm with invalid healthcheck interval.
    act: Create the configuration from the charm.
    assert: Configuration error is raised.
    """
    charm = MockCharmFactory()

    charm.config[HEALTHCHECK_INTERVAL_CONFIG_NAME] = bad_value

    with pytest.raises(ConfigurationError) as err:
        Configuration.from_charm(charm)

    assert str(err.value) == f"Config error: ['interval = {bad_value}: {error_msg}']"
