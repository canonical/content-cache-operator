# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

variable "app_name" {
  description = "Application name for the content-cache charm."
  type        = string
  default     = "content-cache"
}

variable "base" {
  description = "The operating system on which to deploy."
  type        = string
  default     = "ubuntu@24.04"
}

variable "channel" {
  description = "The channel to use when deploying the charm."
  type        = string
  default     = "latest/stable"
}

variable "config" {
  description = "Application config. Details about available options can be found at https://charmhub.io/content-cache/configurations."
  type        = map(string)
  default     = {}
}

variable "constraints" {
  description = "Constraints to apply to the application (e.g. \"arch=amd64\")."
  type        = string
  default     = "arch=amd64"
}

variable "expose" {
  description = "Whether to expose the application publicly over the network."
  type        = bool
  default     = false
}

variable "model_uuid" {
  description = "UUID of the Juju model where the application will be deployed."
  type        = string
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
