# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Module for defining unit test fixtures."""

import pytest
import scenario

from charm import ContentCacheBackendsConfigCharm


@pytest.fixture(name="ctx")
def context_fixture() -> scenario.Context:
    """A scenario Context for ContentCacheBackendsConfigCharm."""
    return scenario.Context(ContentCacheBackendsConfigCharm)


@pytest.fixture(name="ctx_leader")
def context_leader_fixture() -> scenario.Context:
    """A scenario Context for ContentCacheBackendsConfigCharm (leader)."""
    return scenario.Context(ContentCacheBackendsConfigCharm)
