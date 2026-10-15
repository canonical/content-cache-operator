# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

variable "backends_config" {
  description = "Configuration for the content-cache-backends-config charm (location and backends). The default is a placeholder; override it with your own backend(s)."
  type        = map(string)
  default = {
    backends               = "203.0.113.10"
    hostname               = "example.com"
    protocol               = "https"
    healthcheck-ssl-verify = "false"
  }
}

variable "backends_config_channel" {
  description = "The channel to use when deploying the content-cache-backends-config charm. Defaults to `latest/<risk>` (see `risk`) when null."
  type        = string
  default     = null
}

variable "backends_config_revision" {
  description = "Revision number of the content-cache-backends-config charm."
  type        = number
  default     = null
}

variable "certificates_base" {
  description = "The operating system on which to deploy the self-signed-certificates charm."
  type        = string
  default     = "ubuntu@24.04"
}

variable "certificates_channel" {
  description = "The channel to use when deploying the self-signed-certificates charm."
  type        = string
  default     = "latest/stable"
}

variable "content_cache_channel" {
  description = "The channel to use when deploying the content-cache charm. Defaults to `latest/<risk>` (see `risk`) when null."
  type        = string
  default     = null
}

variable "content_cache_revision" {
  description = "Revision number of the content-cache charm."
  type        = number
  default     = null
}

variable "content_cache_units" {
  description = "Number of content-cache units to deploy."
  type        = number
  default     = 1
}

variable "model" {
  description = "Name of the existing Juju model to deploy into."
  type        = string
  default     = "content-cache"
}

variable "model_owner" {
  description = "Owner of the existing Juju model to deploy into (see 'juju show-model')."
  type        = string
  default     = "admin"
}

variable "risk" {
  description = "Default channel risk for the content-cache and content-cache-backends-config charms (used only when their respective `*_channel` variable is null). Deliberately defaults to \"edge\" rather than the CC008-recommended \"stable\" to preserve this module's pre-existing `latest/edge` channel defaults."
  type        = string
  default     = "edge"
  nullable    = false

  validation {
    condition     = contains(["stable", "edge"], var.risk)
    error_message = "risk must be either \"stable\" or \"edge\"."
  }
}
