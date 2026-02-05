A [Juju](https://juju.is/) [charm](https://juju.is/docs/olm/charmed-operators) deploying and managing a static web content cache with Nginx.

This machine charm manages a Nginx instance configured as a content cache. The configuration for the locations of cache is managed with the [Content Cache Backends Config subordinate charm](https://charmhub.io/content-cache-backends-config). Each Content Cache Backends Config charm stores the configuration for a location and the associated set of backends.

This charm should be used for caching static web content. When a client makes a request, this charm checks if the requested content is cached and valid. If not this charm will query the backends hosts for the content to refresh the cache. This process works well for static content that does not change based on the client. For these type of content, the cache can greatly reduce the load on the backend hosts.

The charm simplifies the operation of an Nginx server as a static web content cache. This makes the charm suitable for users looking for a low maintenance way to reduce load on static websites.

## Contributing to this documentation

Documentation is an important part of this project, and we take the same open-source approach to the documentation as 
the code. As such, we welcome community contributions, suggestions and constructive feedback on our documentation. 
Our documentation is hosted on the [Charmhub forum](https://discourse.charmhub.io/) 
to enable easy collaboration. Please use the "Help us improve this documentation" links on each documentation page to 
either directly change something you see that's wrong, ask a question or make a suggestion about a potential change through 
the comments section.

If there's a particular area of documentation that you'd like to see that's missing, please 
[file a bug](https://github.com/canonical/content-cache-operator/issues).

## Project and community

The Content Cache Operator is a member of the Ubuntu family. It's an open-source project that warmly welcomes community 
projects, contributions, suggestions, fixes, and constructive feedback.

- [Code of conduct](https://ubuntu.com/community/code-of-conduct)
- [Get support](https://discourse.charmhub.io/)
- [Join our online chat](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)
- [Contribute](https://github.com/canonical/content-cache-operator/blob/main/content-cache/CONTRIBUTING.md)

Thinking about using the Content Cache Operator for your next project? 
[Get in touch](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)!

# Contents

1. [Tutorial](tutorial)
  1. [Getting started](tutorial/tutorial.md)
1. [How-to](how-to)
  1. [Contribute](how-to/contribute.md)
  2. [Enable COS](how-to/enable-cos.md)
  3. [Enable HTTPS](how-to/enable-https.md)
  4. [Upgrade](how-to/upgrade.md)
