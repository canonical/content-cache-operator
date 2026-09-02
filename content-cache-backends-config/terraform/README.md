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
  the Juju application name.
- **versions.tf** - Defines the Terraform provider version.

## Using the content-cache-backends-config base module in higher level modules

If you want to use `content-cache-backends-config` base module as part of your Terraform module,
import it like shown below:

```text
data "juju_model" "my_model" {
  name = var.model
}

module "content_cache_backends_config" {
  source = "git::https://github.com/canonical/content-cache-operator//content-cache-backends-config/terraform"

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
    name     = module.content_cache.app_name
    endpoint = module.content_cache.endpoints.cache_config
  }
  application {
    name     = module.content_cache_backends_config.app_name
    endpoint = module.content_cache_backends_config.endpoints.cache_config
  }
}
```

The complete list of available integrations can be found [in the Integrations tab][integrations].

[Terraform]: https://www.terraform.io/
[Terraform Juju provider]: https://registry.terraform.io/providers/juju/juju/latest
[Juju]: https://juju.is
[integrations]: https://charmhub.io/content-cache-backends-config/integrations
