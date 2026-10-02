# Content cache charms

This repository contains the code for two charms:
1. `content-cache`: A machine charm managing a nginx instance configured as a content cache. See the [content-cache README](content-cache/README.md) for more information.
2. `content-cache-backends-config`: A subordinate charm providing the configuration required to expose a set of backend services. See the [content-cache-backends-config README](content-cache-backends-config/README.md) for more information.

For published user documentation, see the official [Content cache charms documentation](https://canonical.com/juju/docs/content-cache-charms).

## Repository layout

```text
content-cache/                         # Principal machine charm that deploys and manages the NGINX content cache.
  src/                                 # Charm source code.
  tests/                               # Unit and integration tests for the content-cache charm.
  terraform/                           # Base Terraform module for deploying the content-cache charm.

content-cache-backends-config/         # Subordinate charm that injects backend/location configuration into content-cache.
  src/                                 # Charm source code.
  tests/                               # Unit and integration tests for the subordinate configuration charm.
  terraform/                           # Base Terraform module for deploying content-cache-backends-config.

docs/                                  # Canonical Sphinx documentation source.
  tutorial/                            # In-repo tutorial source for a deployment with ingress configurator and HAProxy.
  how-to/                              # Operational guides, including HTTPS, COS, upgrade, and contribution topics.
  reference/                           # Component and deployment architecture references.
  explanation/                         # Design, caching behavior, and security explanations.

terraform/                             # Example Terraform composition using both charms and self-signed certificates.

styles/                                # Documentation style configuration used by repository checks.
```
## Components

| Component | Path | Role |  |
| --- | --- | --- | --- |
| `content-cache` | [`content-cache/`](content-cache/) | A machine charm managing a nginx instance configured as a content cache. |  |
| `content-cache-backends-config` | [`content-cache-backends-config/`](content-cache-backends-config/) | A subordinate charm providing the configuration required to expose a set of backend services. |  |


### Charmhub

| Name | Listing |
| --- | --- |
| `content-cache` | https://charmhub.io/content-cache |
| `content-cache-backends-config` | https://charmhub.io/content-cache-backends-config |

## Get started

To begin, refer to the in-repo [Content Cache tutorial](docs/tutorial/index.md) for step-by-step instructions. For component-specific context, see the [`content-cache` README](content-cache/README.md) and the [`content-cache-backends-config` README](content-cache-backends-config/README.md).

For Terraform-based deployments, use the repository-level [example composition](terraform/README.md) or the component base modules in [`content-cache/terraform/README.md`](content-cache/terraform/README.md) and [`content-cache-backends-config/terraform/README.md`](content-cache-backends-config/terraform/README.md).

## Integrations

The main integration between the two in-repo charms is `cache-config` with interface `content-cache-config`:

- `content-cache` provides `cache-config`.
- `content-cache-backends-config` requires `cache-config` as a subordinate charm.

`content-cache` also supports certificate, CA-transfer, COS, and peer integrations. See [`docs/reference/deployment-architecture.md`](docs/reference/deployment-architecture.md) and [`docs/reference/components.md`](docs/reference/components.md) for the verified relation and component details.


## Documentation

Our documentation is stored in the `docs` directory and
can be viewed at https://canonical.com/juju/docs/content-cache-charms.
It is based on the Canonical Sphinx Stack and hosted on
[Read the Docs](https://about.readthedocs.com/). In structuring, the
documentation employs the [Diátaxis](https://diataxis.fr/) approach.

You may open a pull request with your documentation changes, or you can
[file a bug](https://github.com/canonical/content-cache-operator/issues) to
provide constructive feedback or suggestions.

To run the documentation locally before submitting your changes:

```bash
cd docs
make run
```

GitHub runs automatic checks on the documentation to verify spelling,
validate links and style guide compliance.

You can (and should) run the same checks locally:

```bash
make spelling
make linkcheck
make vale
make lint-md
```

## Project and community

The Content Cache Project is a member of the Ubuntu family. It is an
open source project that warmly welcomes community projects, contributions,
suggestions, fixes and constructive feedback.

* [Code of conduct](https://ubuntu.com/community/code-of-conduct)
* [Get support](https://discourse.charmhub.io/)
* [Issues](https://github.com/canonical/content-cache-operator/issues)
* [Matrix](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)
