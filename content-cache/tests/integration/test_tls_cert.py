# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test for the content-cache charm with tls-certificates integration."""

import pytest


@pytest.mark.skip(
    reason=(
        "TLS termination for incoming traffic is no longer handled by the content-cache charm. "
        "Client-facing TLS is expected to be managed by an upstream ingress component."
    )
)
async def test_integrate_with_data_then_cert() -> None:
    """Placeholder — TLS termination removed from this charm."""


@pytest.mark.skip(
    reason=(
        "TLS termination for incoming traffic is no longer handled by the content-cache charm. "
        "Client-facing TLS is expected to be managed by an upstream ingress component."
    )
)
async def test_integrate_with_cert_then_data() -> None:
    """Placeholder — TLS termination removed from this charm."""
