# Content Cache deployment (example composition)

This folder contains an example [Terraform][Terraform] deployment that composes the
`content-cache` and `content-cache-backends-config` base modules together with a
`self-signed-certificates` provider, so that the stack can be brought up for a GitOps /
staging test.

It deploys and integrates:

- **content-cache** (principal, exposed) — the nginx content cache.
- **content-cache-backends-config** (subordinate) — location and backends configuration,
  integrated with `content-cache` over `cache-config`.
- **content-cache-certs** (`self-signed-certificates`) — provides TLS certificates to
  `content-cache` over `certificates`.

## Prerequisites

- A bootstrapped Juju controller and an **existing** model (the module looks the model up
  with a `juju_model` data source; it does not create it).
- The [Terraform Juju provider][Terraform Juju provider] configured (via environment
  variables or a `provider "juju" {}` block in a `providers.tf` file).

## Usage

```bash
# Point the provider at your controller/model (or use a providers.tf file).
export JUJU_CONTROLLER_ADDRESSES=...
export JUJU_USERNAME=...
export JUJU_PASSWORD=...
export JUJU_CA_CERT="$(juju controller-config ca-cert)"

terraform init
terraform apply -var="model=content-cache"
```

Override any of the inputs (charm channels, revisions, backends config, etc.) with
`-var`/`-var-file` as needed. See `variables.tf` for the full list.

## Note on providers

This example intentionally does not pin a controller, Vault or OpenStack provider
configuration — those are environment specific. Supply your own `providers.tf`
(git-ignored in the base modules) or configure the provider through environment variables.

[Terraform]: https://www.terraform.io/
[Terraform Juju provider]: https://registry.terraform.io/providers/juju/juju/latest
