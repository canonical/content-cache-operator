# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Module for defining unit test fixtures."""

import pytest
from ops.testing import Harness

from charm import ContentCacheBackendsConfigCharm


@pytest.fixture(name="harness", scope="function")
def harness_fixture():
    """The ops testing harness fixture."""
    harness = Harness(ContentCacheBackendsConfigCharm)
    harness.set_leader(True)
    harness.begin_with_initial_hooks()
    yield harness
    harness.cleanup()


@pytest.fixture(name="charm", scope="function")
def charm_fixture(harness: Harness):
    """The charm fixture"""
    return harness.charm
