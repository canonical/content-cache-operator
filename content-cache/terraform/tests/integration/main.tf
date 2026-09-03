# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

terraform {
  required_version = ">= 1.0"
  required_providers {
    juju = {
      version = "> 1.1.0"
      source  = "juju/juju"
    }
    external = {
      version = "> 2"
      source  = "hashicorp/external"
    }
  }
}

provider "juju" {}

variable "model_uuid" {
  type = string
}

resource "juju_application" "self_signed_certificates" {
  model_uuid = var.model_uuid
  charm {
    name    = "self-signed-certificates"
    channel = "latest/stable"
  }
}

resource "juju_integration" "content_cache_certificates" {
  model_uuid = var.model_uuid

  application {
    name     = "content-cache"
    endpoint = "certificates"
  }

  application {
    name     = juju_application.self_signed_certificates.name
    endpoint = "certificates"
  }
}

# tflint-ignore: terraform_unused_declarations
data "external" "content_cache_status" {
  program = ["bash", "${path.module}/wait-for-status.sh", var.model_uuid]

  depends_on = [
    juju_integration.content_cache_certificates
  ]
}
