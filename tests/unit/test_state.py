# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from ipaddress import IPv4Address

import pytest

from errors import ConfigurationError
from src.state import HOSTNAME_CONFIG_NAME, PATH_CONFIG_NAME
from state import BACKENDS_CONFIG_NAME, LocationConfig
from tests.unit.conftest import SAMPLE_INTEGRATION_DATA


def test_config_from_integration_data():
    """
    arrange: Valid sample integration data.
    act: Create the config from the data.
    assert: The configurations are correctly parsed.
    """
    config = LocationConfig.from_integration_data(SAMPLE_INTEGRATION_DATA)
    assert config.hostname == "example.com"
    assert config.backends == (IPv4Address("10.10.1.1"), IPv4Address("10.10.2.2"))
    assert config.protocol == "https"


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
