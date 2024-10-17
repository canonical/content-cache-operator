# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from ipaddress import IPv4Address

import pytest

from errors import ConfigurationError
from src.state import HOSTNAME_CONFIG_NAME, PATH_CONFIG_NAME
from state import (
    BACKENDS_CONFIG_NAME,
    BACKENDS_PATH_CONFIG_NAME,
    HEALTH_CHECK_PATH_CONFIG_NAME,
    PROTOCOL_CONFIG_NAME,
    PROXY_CACHE_VALID_CONFIG_NAME,
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
    assert config.hostname == "example.com"
    assert config.path == "/"
    assert config.backends == (IPv4Address("10.10.1.1"), IPv4Address("10.10.2.2"))
    assert config.protocol == "https"
    assert config.health_check_path == "/"
    assert config.health_check_interval == 30
    assert config.backends_path == "/"
    assert config.proxy_cache_valid == ("200 302 1h", "404 1m")


def test_config_subdomain_integration_data():
    """
    arrange: Valid sample integration data with subdomain in hostname.
    act: Create the config from the data.
    assert: The configurations are correctly parsed.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[HOSTNAME_CONFIG_NAME] = "hello.example.com"
    config = LocationConfig.from_integration_data(data)
    assert config.hostname == "hello.example.com"
    assert config.path == "/"
    assert config.backends == (IPv4Address("10.10.1.1"), IPv4Address("10.10.2.2"))
    assert config.protocol == "https"
    assert config.health_check_path == "/"
    assert config.health_check_interval == 30
    assert config.backends_path == "/"
    assert config.proxy_cache_valid == ("200 302 1h", "404 1m")


def test_config_with_empty_hostname_integration_data():
    """
    arrange: Sample integration data with empty hostname.
    act: Create the config from the data.
    assert: Exception raised with the correct error message.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[HOSTNAME_CONFIG_NAME] = ""

    with pytest.raises(ConfigurationError) as err:
        LocationConfig.from_integration_data(data)

    assert (
        str(err.value) == "Config error: ['hostname = : String should have at least 1 character']"
    )


def test_config_with_long_hostname_integration_data():
    """
    arrange: Sample integration data with long hostname.
    act: Create the config from the data.
    assert: Exception raised with the correct error message.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[HOSTNAME_CONFIG_NAME] = "a" * 256

    with pytest.raises(ConfigurationError) as err:
        LocationConfig.from_integration_data(data)

    assert "Value error, Hostname cannot be longer than 255" in str(err.value)


def test_config_with_invalid_hostname_integration_data():
    """
    arrange: Sample integration data with hostname with invalid character.
    act: Create the config from the data.
    assert: Exception raised with the correct error message.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[HOSTNAME_CONFIG_NAME] = "example?.com"

    with pytest.raises(ConfigurationError) as err:
        LocationConfig.from_integration_data(data)

    assert "must be less than 64 in length, and consist of alphanumeric and hyphen" in str(
        err.value
    )


def test_config_with_empty_path_integration_data():
    """
    arrange: Sample integration data with empty path.
    act: Create the config from the data.
    assert: Exception raised with the correct error message.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[PATH_CONFIG_NAME] = ""

    with pytest.raises(ConfigurationError) as err:
        LocationConfig.from_integration_data(data)

    assert str(err.value) == "Config error: ['path = : String should have at least 1 character']"


def test_config_with_invalid_path_integration_data():
    """
    arrange: Sample integration data with path with invalid character.
    act: Create the config from the data.
    assert: Exception raised with the correct error message.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[PATH_CONFIG_NAME] = "/^"

    with pytest.raises(ConfigurationError) as err:
        LocationConfig.from_integration_data(data)

    assert (
        str(err.value)
        == "Config error: ['path = /^: Value error, Path contains non-allowed character']"
    )


def test_config_long_path_integration_data():
    """
    arrange: Valid sample integration data with long paths.
    act: Create the config from the data.
    assert: The configurations are correctly parsed.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[PATH_CONFIG_NAME] = "/path/to/somewhere"
    data[HEALTH_CHECK_PATH_CONFIG_NAME] = "/path$/to&/here!"
    data[BACKENDS_PATH_CONFIG_NAME] = "/here/there"
    config = LocationConfig.from_integration_data(data)
    assert config.hostname == "example.com"
    assert config.path == "/path/to/somewhere"
    assert config.backends == (IPv4Address("10.10.1.1"), IPv4Address("10.10.2.2"))
    assert config.protocol == "https"
    assert config.health_check_path == "/path$/to&/here!"
    assert config.health_check_interval == 30
    assert config.backends_path == "/here/there"
    assert config.proxy_cache_valid == ("200 302 1h", "404 1m")


@pytest.mark.parametrize(
    "invalid_backends, error_message",
    [
        pytest.param("[]", "Empty backends found", id="empty backends"),
        pytest.param("value", "Unable to parse backends as json", id="none json value"),
        pytest.param(
            '{"value": 1}', "Unable to convert backends to list", id="incorrect backends format"
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
    data[BACKENDS_CONFIG_NAME] = invalid_backends

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
    data[PROTOCOL_CONFIG_NAME] = "http"
    config = LocationConfig.from_integration_data(data)
    assert config.hostname == "example.com"
    assert config.path == "/"
    assert config.backends == (IPv4Address("10.10.1.1"), IPv4Address("10.10.2.2"))
    assert config.protocol == "http"
    assert config.health_check_path == "/"
    assert config.health_check_interval == 30
    assert config.backends_path == "/"
    assert config.proxy_cache_valid == ("200 302 1h", "404 1m")


def test_config_invalid_format_proxy_cache_valid_integration_data():
    """
    arrange: Sample integration data with proxy_cache_valid of invalid format.
    act: Create the config from the data.
    assert: Exception raised with the correct error message.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[PROXY_CACHE_VALID_CONFIG_NAME] = "invalid"

    with pytest.raises(ConfigurationError) as err:
        LocationConfig.from_integration_data(data)

    assert "Unable to parse proxy_cache_valid: invalid" in str(err.value)


def test_config_proxy_cache_valid_without_time_integration_data():
    """
    arrange: Sample integration data with proxy_cache_valid without time.
    act: Create the config from the data.
    assert: Exception raised with the correct error message.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[PROXY_CACHE_VALID_CONFIG_NAME] = '["200"]'

    with pytest.raises(ConfigurationError) as err:
        LocationConfig.from_integration_data(data)

    assert "Value error, Invalid item in proxy_cache_valid: 200" in str(err.value)


def test_config_non_list_proxy_cache_valid_integration_data():
    """
    arrange: Sample integration data with non-list proxy_cache_valid.
    act: Create the config from the data.
    assert: Exception raised with the correct error message.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[PROXY_CACHE_VALID_CONFIG_NAME] = '{"hello": 10}'

    with pytest.raises(ConfigurationError) as err:
        LocationConfig.from_integration_data(data)

    assert 'The proxy_cache_valid is not a list: {"hello": 10}' in str(err.value)


def test_config_invalid_time_proxy_cache_valid_integration_data():
    """
    arrange: Sample integration data with proxy_cache_valid with invalid time.
    act: Create the config from the data.
    assert: Exception raised with the correct error message.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 302 1y"]'

    with pytest.raises(ConfigurationError) as err:
        LocationConfig.from_integration_data(data)

    assert "Value error, Invalid time for proxy_cache_valid: 1y" in str(err.value)


def test_config_non_int_time_proxy_cache_valid_integration_data():
    """
    arrange: Sample integration data with proxy_cache_valid with non-int time.
    act: Create the config from the data.
    assert: Exception raised with the correct error message.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 302 tend"]'

    with pytest.raises(ConfigurationError) as err:
        LocationConfig.from_integration_data(data)

    assert "Value error, Non-int time in proxy_cache_valid: tend" in str(err.value)


def test_config_negative_time_proxy_cache_valid_integration_data():
    """
    arrange: Sample integration data with proxy_cache_valid with negative time.
    act: Create the config from the data.
    assert: Exception raised with the correct error message.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 302 -10d"]'

    with pytest.raises(ConfigurationError) as err:
        LocationConfig.from_integration_data(data)

    assert "Value error, Time must be positive int for proxy_cache_valid: -10d" in str(err.value)


def test_config_non_int_status_code_proxy_cache_valid_integration_data():
    """
    arrange: Sample integration data with proxy_cache_valid with non-int status code.
    act: Create the config from the data.
    assert: Exception raised with the correct error message.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[PROXY_CACHE_VALID_CONFIG_NAME] = '["ok 30m"]'

    with pytest.raises(ConfigurationError) as err:
        LocationConfig.from_integration_data(data)

    assert "Value error, Non-int status code in proxy_cache_valid: ok" in str(err.value)


def test_config_invalid_status_code_proxy_cache_valid_integration_data():
    """
    arrange: Sample integration data with proxy_cache_valid with invalid status code.
    act: Create the config from the data.
    assert: Exception raised with the correct error message.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[PROXY_CACHE_VALID_CONFIG_NAME] = '["200 99 30m"]'

    with pytest.raises(ConfigurationError) as err:
        LocationConfig.from_integration_data(data)

    assert "Value error, Invalid status code in proxy_cache_valid: 99" in str(err.value)
