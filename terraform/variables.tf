# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

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

variable "content_cache_channel" {
  description = "The channel to use when deploying the content-cache charm."
  type        = string
  default     = "latest/edge"
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

variable "backends_config_channel" {
  description = "The channel to use when deploying the content-cache-backends-config charm."
  type        = string
  default     = "latest/edge"
}

variable "backends_config_revision" {
  description = "Revision number of the content-cache-backends-config charm."
  type        = number
  default     = null
}

variable "backends_config" {
  description = "Configuration for the content-cache-backends-config charm (location and backends)."
  type        = map(string)
  default = {
    backends               = "91.189.95.14"
    hostname               = "discourse.staging.ubuntu.com"
    protocol               = "https"
    healthcheck-ssl-verify = "false"
  }
}

variable "certificates_channel" {
  description = "The channel to use when deploying the self-signed-certificates charm."
  type        = string
  default     = "latest/stable"
}

variable "certificates_base" {
  description = "The operating system on which to deploy the self-signed-certificates charm."
  type        = string
  default     = "ubuntu@24.04"
}
