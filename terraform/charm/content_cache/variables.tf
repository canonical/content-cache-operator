# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

variable "app_name" {
  description = "Application name for the content-cache charm."
  type        = string
  default     = "content-cache"
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
  description = "Application config. Details about available options can be found at https://charmhub.io/content-cache/configurations."
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

variable "units" {
  description = "Number of units to deploy."
  type        = number
  default     = 1
}
