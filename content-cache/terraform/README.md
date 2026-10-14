# Content Cache Terraform module

This folder contains a base [Terraform][Terraform] module for the `content-cache` charm.

The module uses the [Terraform Juju provider][Terraform Juju provider] to model the charm
deployment onto any machine environment managed by [Juju][Juju].

## Module structure

- **main.tf** - Defines the Juju application to be deployed.
- **variables.tf** - Allows customization of the deployment. Also models the charm configuration,
  except for exposing the deployment options (Juju model, channel or application name).
- **outputs.tf** - Integrates the module with other Terraform modules, primarily
  by defining potential integration endpoints (charm integrations), but also by exposing
  the deployed Juju application.
- **terraform.tf** - Defines the Terraform and Juju provider version requirements.

## Using the content-cache base module in higher level modules

If you want to use `content-cache` base module as part of your Terraform module, import it
like shown below:

```text
data "juju_model" "my_model" {
  name = var.model
}

module "content_cache" {
  source = "git::https://github.com/canonical/content-cache-operator//content-cache/terraform?ref=tf-1.0.0"

  model_uuid = data.juju_model.my_model.uuid
  # (Customize configuration variables here if needed)
}
```

Create integrations, for instance:

```text
resource "juju_integration" "content_cache_certificates" {
  model_uuid = data.juju_model.my_model.uuid
  application {
    name     = module.content_cache.application.name
    endpoint = module.content_cache.requires.certificates.endpoint
  }
  application {
    name     = "self-signed-certificates"
    endpoint = "certificates"
  }
}
```

The complete list of available integrations can be found [in the Integrations tab][content-cache-integrations].

[Terraform]: https://www.terraform.io/
[Terraform Juju provider]: https://registry.terraform.io/providers/juju/juju/latest
[Juju]: https://juju.is
[content-cache-integrations]: https://charmhub.io/content-cache/integrations

<!-- BEGIN_TF_DOCS -->
<!-- END_TF_DOCS -->
