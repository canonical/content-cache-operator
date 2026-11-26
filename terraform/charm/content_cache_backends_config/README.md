# Content Cache Backends Config Terraform module

This folder contains a base [Terraform][Terraform] module for the `content-cache-backends-config`
charm.

The module uses the [Terraform Juju provider][Terraform Juju provider] to model the charm
deployment onto any machine environment managed by [Juju][Juju].

`content-cache-backends-config` is a subordinate charm. It must be integrated with the
`content-cache` charm (over the `cache-config` endpoint) to be functional, and it is deployed
with zero units of its own.

## Module structure

- **main.tf** - Defines the Juju application to be deployed.
- **variables.tf** - Allows customization of the deployment. Also models the charm configuration,
  except for exposing the deployment options (Juju model, channel or application name).
- **outputs.tf** - Integrates the module with other Terraform modules, primarily
  by defining potential integration endpoints (charm integrations), but also by exposing
  the deployed Juju application.
- **terraform.tf** - Defines the Terraform and Juju provider version requirements.

## Using the content-cache-backends-config base module in higher level modules

If you want to use `content-cache-backends-config` base module as part of your Terraform module,
import it like shown below:

```text
data "juju_model" "my_model" {
  name = var.model
}

module "content_cache_backends_config" {
  source = "git::https://github.com/canonical/content-cache-operator//terraform/charm/content_cache_backends_config?ref=tf-1.0.0"

  model_uuid = data.juju_model.my_model.uuid
  config = {
    backends = "10.0.0.1"
    hostname = "example.com"
    protocol = "https"
  }
}
```

Integrate it with the `content-cache` principal:

```text
resource "juju_integration" "cache_config" {
  model_uuid = data.juju_model.my_model.uuid
  application {
    name     = module.content_cache.application.name
    endpoint = module.content_cache.provides.cache_config.endpoint
  }
  application {
    name     = module.content_cache_backends_config.application.name
    endpoint = module.content_cache_backends_config.requires.cache_config.endpoint
  }
}
```

The complete list of available integrations can be found [in the Integrations tab][integrations].

[Terraform]: https://www.terraform.io/
[Terraform Juju provider]: https://registry.terraform.io/providers/juju/juju/latest
[Juju]: https://canonical.com/juju
[integrations]: https://charmhub.io/content-cache-backends-config/integrations

<!-- vale off -->
<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | ~> 1.12 |
| <a name="requirement_juju"></a> [juju](#requirement\_juju) | ~> 2.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_juju"></a> [juju](#provider\_juju) | ~> 2.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [juju_application.content_cache_backends_config](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/application) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_app_name"></a> [app\_name](#input\_app\_name) | Application name for the content-cache-backends-config charm. | `string` | `"content-cache-backends-config"` | no |
| <a name="input_base"></a> [base](#input\_base) | The operating system on which to deploy. Defaults to the charm's default base when null. | `string` | `null` | no |
| <a name="input_channel"></a> [channel](#input\_channel) | The channel to use when deploying the charm. | `string` | `"latest/stable"` | no |
| <a name="input_config"></a> [config](#input\_config) | Application config. Details about available options can be found at https://charmhub.io/content-cache-backends-config/configurations. | `map(string)` | `{}` | no |
| <a name="input_constraints"></a> [constraints](#input\_constraints) | Constraints to apply to the application (e.g. "arch=amd64"). | `string` | `null` | no |
| <a name="input_expose"></a> [expose](#input\_expose) | Juju exposure settings. Set to `{}` (the default) to expose the application publicly with no restrictions, or set `cidrs`/`endpoints`/`spaces` to restrict exposure, or set to `null` to keep the application unexposed. | <pre>object({<br/>    cidrs     = optional(string)<br/>    endpoints = optional(string)<br/>    spaces    = optional(string)<br/>  })</pre> | `{}` | no |
| <a name="input_model_uuid"></a> [model\_uuid](#input\_model\_uuid) | UUID of the Juju model where the application will be deployed. | `string` | n/a | yes |
| <a name="input_revision"></a> [revision](#input\_revision) | Revision number of the charm. | `number` | `null` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_application"></a> [application](#output\_application) | The deployed content-cache-backends-config juju\_application object. |
| <a name="output_requires"></a> [requires](#output\_requires) | Map of the integration endpoints required by the content-cache-backends-config charm. |
<!-- END_TF_DOCS -->
<!-- vale on -->
