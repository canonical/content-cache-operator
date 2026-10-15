# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

locals {
  # Fall back to the risk-derived channel only when the caller does not pin
  # an explicit channel for the charm.
  backends_config_channel = coalesce(var.backends_config_channel, "latest/${var.risk}")
  content_cache_channel   = coalesce(var.content_cache_channel, "latest/${var.risk}")
}
