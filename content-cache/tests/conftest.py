# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Test setup."""

from pytest import Parser


def pytest_addoption(parser: Parser):
    """Add pytest options.

    Args:
        parser: The pytest argument parser.
    """
    parser.addoption("--charm-file", action="store", help="The prebuilt content-cache charm file.")
    parser.addoption(
        "--config-charm-file",
        action="store",
        help="The prebuilt content-cache-backends-config charm file.",
    )

    parser.addoption(
        "--use-existing-app",
        action="append",
        default=[],
        help="List of apps to use instead of deploying them.",
    )
