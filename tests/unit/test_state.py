# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from ipaddress import IPv4Address

import pytest

from errors import ConfigurationError
from state import BACKENDS_CONFIG_NAME, LOCATION_CONFIG_NAME, LocationConfig
from tests.unit.conftest import SAMPLE_INTEGRATION_DATA


def test_config_from_integration_data():
    """
    arrange: Valid sample integration data.
    act: Create the config from the data.
    assert: The configurations are correctly parsed.
    """
    config = LocationConfig.from_integration_data(SAMPLE_INTEGRATION_DATA)
    assert config.location == "example.com"
    assert config.backends == (IPv4Address("10.10.1.1"), IPv4Address("10.10.2.2"))
    assert config.protocol == "https"


def test_config_with_empty_location_integration_data():
    """
    arrange: Sample integration data with empty location.
    act: Create the config from the data.
    assert: Exception raised with the correct error message.
    """
    data = dict(SAMPLE_INTEGRATION_DATA)
    data[LOCATION_CONFIG_NAME] = ""

    with pytest.raises(ConfigurationError) as err:
        LocationConfig.from_integration_data(data)

    assert (
        str(err.value) == "Config error: ['location = : String should have at least 1 character']"
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
