# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

variable "app_name" {
  description = "Application name for the content-cache-backends-config charm."
  type        = string
  default     = "content-cache-backends-config"
  nullable    = false
}

variable "base" {
  description = "The operating system on which to deploy. Defaults to the charm's default base when null."
  type        = string
  default     = null
}

variable "channel" {
  description = "The channel to use when deploying the charm."
  type        = string
  default     = "latest/stable"
  nullable    = false
}

variable "config" {
  description = "Application config. Details about available options can be found at https://charmhub.io/content-cache-backends-config/configurations."
  type        = map(string)
  default     = {}
}

variable "constraints" {
  description = "Constraints to apply to the application (e.g. \"arch=amd64\")."
  type        = string
  default     = null
}

variable "expose" {
  description = "Juju exposure settings. Set to `{}` (the default) to expose the application publicly with no restrictions, or set `cidrs`/`endpoints`/`spaces` to restrict exposure, or set to `null` to keep the application unexposed."
  type = object({
    cidrs     = optional(string)
    endpoints = optional(string)
    spaces    = optional(string)
  })
  default  = {}
  nullable = true
}

variable "model_uuid" {
  description = "UUID of the Juju model where the application will be deployed."
  type        = string
  nullable    = false
}

variable "revision" {
  description = "Revision number of the charm."
  type        = number
  default     = null
}

# This is a subordinate charm; it has no units of its own and is deployed
# onto the units of the principal it is integrated with, so the `units`
# variable is intentionally omitted (not even set to 0) due to a provider
# bug: https://github.com/juju/terraform-provider-juju/issues/1003
