# Content cache operator

A [Juju](https://juju.is/) [charm](https://juju.is/docs/olm/charmed-operators) deploying and managing a static web content cache with nginx.

This machine charm manages a nginx instance configured as a content cache. Backends are configured through the `cache-config` relation (interface `content-cache-config`), provided either by the [Content Cache Backends Config subordinate charm](https://charmhub.io/content-cache-backends-config) or by the [Ingress configurator charm](https://charmhub.io/ingress-configurator), which can also be paired with [HAProxy](https://charmhub.io/haproxy) for hostname/path-based routing, TLS termination, and other ingress features.

This charm should be used for caching static web content. When a client makes a request, this charm checks if the requested content is cached and valid. If not this charm will query the backends hosts for the content to refresh the cache. This process works well for static content that does not change based on the client. For this type of content, the cache can greatly reduce the load on the backend hosts.

The charm simplifies the operation of an nginx server as a static web content cache. This makes the charm suitable for users looking for a low maintenance way to reduce load on static websites.

## Get started

To begin, refer to the [Content Cache tutorial](https://canonical.com/juju/docs/content-cache-charms/latest/tutorial/) for step-by-step instructions.

## Integrations

You can find the full list of integrations in the [Charmhub documentation](https://charmhub.io/content-cache/integrations).


## Learn more

- [Charm documentation](https://canonical.com/juju/docs/content-cache-charms/latest/)
- [Developer documentation](https://nginx.org/en/docs/dev/development_guide.html)
- [Official webpage](https://www.nginx.com/)
- [Troubleshooting](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)

## Project and community

The Content Cache Operator is a member of the Ubuntu family. It is an
open source project that warmly welcomes community projects, contributions,
suggestions, fixes and constructive feedback.
* [Code of conduct](https://ubuntu.com/community/code-of-conduct)
* [Get support](https://discourse.charmhub.io/)
* [Issues](https://github.com/canonical/content-cache-operator/issues)
* [Contribute](https://github.com/canonical/content-cache-operator/blob/main/content-cache/CONTRIBUTING.md)
* [Matrix](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)
