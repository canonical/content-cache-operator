<!--
Avoid using this README file for information that is maintained or published elsewhere, e.g.:

* metadata.yaml > published on Charmhub
* documentation > published on (or linked to from) Charmhub
* detailed contribution guide > documentation or CONTRIBUTING.md

Use links instead.
-->

# Content cache backends config operator

A [Juju](https://juju.is/) [subordinate](https://juju.is/docs/sdk/charm-taxonomy#heading--subordinate-charms) [charm](https://juju.is/docs/olm/charmed-operators) to the [Content Cache charm](https://charmhub.io/content-cache) which provides the Content Cache charm with the configuration required to expose a set of backend services behind caching capabilities of the Content Cache charm.

This charm should be integrated with the Content Cache charm to inject the correct configurations into the content cache charm. For more information see the [Content Cache charm](https://charmhub.io/content-cache).

## Get started

The Content Cache Backends Config Charm requires the deployment of the Content Cache charm. To begin, refer to the [Content Cache tutorial](https://github.com/canonical/content-cache-operator/blob/main/content-cache/docs/tutorial/quick-start.md) for step-by-step instructions.

### Basic operations

Some of the Content Cache Backends Config Charm configurations include:

- backends
- backends-path
- fail-timeout
- hostname

and many more. For the complete list of configurations and their usage, refer to the [Charmhub Documentation](https://charmhub.io/content-cache-backends-config/configurations).

## Integrations

The Content Cache Backends Config Charm needs to be integrated with the Content Cache charm. For more details regarding the integration, refer to the [the Charmhub documentation](https://charmhub.io/content-cache-backends-config/integrations).

## Learn more

- [Read more](https://charmhub.io/content-cache-backends-config)
- [Troubleshooting](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)

## Project and community

The Content Cache Backends Config Operator is a member of the Ubuntu family. It is an
open source project that warmly welcomes community projects, contributions,
suggestions, fixes and constructive feedback.
* [Code of conduct](https://ubuntu.com/community/code-of-conduct)
* [Get support](https://discourse.charmhub.io/)
* [Issues](https://github.com/canonical/content-cache-operator/issues)
* [Contribute](https://github.com/canonical/content-cache-operator/blob/main/content-cache-backends-config/CONTRIBUTING.md)
* [Matrix](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)