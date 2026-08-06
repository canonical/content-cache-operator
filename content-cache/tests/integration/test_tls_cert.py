# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test for the content-cache charm with tls-certificates integration."""

import pytest

_SKIP_REASON = (
    "Hostname-based TLS termination has been replaced. The content-cache charm will "
    "still terminate TLS for HAProxy→content-cache traffic, but via a single cache "
    "certificate obtained through the tls-certificates relation (not per-hostname). "
    "Integration tests for the new TLS termination will be added when that story is "
    "implemented."
)


@pytest.mark.skip(reason=_SKIP_REASON)
async def test_integrate_with_data_then_cert() -> None:
    """Placeholder — hostname-based TLS replaced by cache-cert TLS termination story."""


@pytest.mark.skip(reason=_SKIP_REASON)
async def test_integrate_with_cert_then_data() -> None:
    """Placeholder — hostname-based TLS replaced by cache-cert TLS termination story."""
