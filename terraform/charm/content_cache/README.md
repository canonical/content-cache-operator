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
  source = "git::https://github.com/canonical/content-cache-operator//terraform/charm/content_cache?ref=tf-1.0.0"

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
[Juju]: https://canonical.com/juju
[content-cache-integrations]: https://charmhub.io/content-cache/integrations

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
| [juju_application.content_cache](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/application) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_app_name"></a> [app\_name](#input\_app\_name) | Application name for the content-cache charm. | `string` | `"content-cache"` | no |
| <a name="input_base"></a> [base](#input\_base) | The operating system on which to deploy. Defaults to the charm's default base when null. | `string` | `null` | no |
| <a name="input_channel"></a> [channel](#input\_channel) | The channel to use when deploying the charm. | `string` | `"latest/stable"` | no |
| <a name="input_config"></a> [config](#input\_config) | Application config. Details about available options can be found at https://charmhub.io/content-cache/configurations. | `map(string)` | `{}` | no |
| <a name="input_constraints"></a> [constraints](#input\_constraints) | Constraints to apply to the application (e.g. "arch=amd64"). | `string` | `null` | no |
| <a name="input_expose"></a> [expose](#input\_expose) | Juju exposure settings. Set to `{}` (the default) to expose the application publicly with no restrictions, or set `cidrs`/`endpoints`/`spaces` to restrict exposure, or set to `null` to keep the application unexposed. | <pre>object({<br/>    cidrs     = optional(string)<br/>    endpoints = optional(string)<br/>    spaces    = optional(string)<br/>  })</pre> | `{}` | no |
| <a name="input_model_uuid"></a> [model\_uuid](#input\_model\_uuid) | UUID of the Juju model where the application will be deployed. | `string` | n/a | yes |
| <a name="input_revision"></a> [revision](#input\_revision) | Revision number of the charm. | `number` | `null` | no |
| <a name="input_units"></a> [units](#input\_units) | Number of units to deploy. | `number` | `1` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_application"></a> [application](#output\_application) | The deployed content-cache juju\_application object. |
| <a name="output_provides"></a> [provides](#output\_provides) | Map of the integration endpoints provided by the content-cache charm. |
| <a name="output_requires"></a> [requires](#output\_requires) | Map of the integration endpoints required by the content-cache charm. |
<!-- END_TF_DOCS -->
<!-- vale on -->
