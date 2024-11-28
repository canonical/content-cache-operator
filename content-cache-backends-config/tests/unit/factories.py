# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Factory for mocks."""

import typing
from unittest.mock import MagicMock

import factory

from src.state import (
    BACKENDS_CONFIG_NAME,
    BACKENDS_PATH_CONFIG_NAME,
    FAIL_TIMEOUT_CONFIG_NAME,
    HOSTNAME_CONFIG_NAME,
    PATH_CONFIG_NAME,
    PROTOCOL_CONFIG_NAME,
    PROXY_CACHE_VALID_CONFIG_NAME,
)

T = typing.TypeVar("T")

# The factory-boy usage results in no public methods.
# pylint: disable=too-few-public-methods

# Disable DCO060 docstring attribute check, as mock does not need these.


class MockUnitFactory(factory.Factory):
    """Mock charm unit."""  # noqa: DCO060

    class Meta:
        """Configuration for factory."""  # noqa: DCO060

        model = MagicMock

    name: str


class MockCharmFactory(factory.Factory):
    """Mock the content-cache-backend-config charm."""  # noqa: DCO060

    class Meta:
        """Configuration for the factory."""  # noqa: DCO060

        model = MagicMock

    app = MagicMock
    unit = MockUnitFactory
    config = factory.Dict(
        {
            HOSTNAME_CONFIG_NAME: "example.com",
            PATH_CONFIG_NAME: "/",
            BACKENDS_CONFIG_NAME: "10.10.1.1, 10.10.2.2",
            PROTOCOL_CONFIG_NAME: "https",
            FAIL_TIMEOUT_CONFIG_NAME: "30s",
            BACKENDS_PATH_CONFIG_NAME: "/",
            PROXY_CACHE_VALID_CONFIG_NAME: "[]",
        }
    )
