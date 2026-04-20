---
myst:
  html_meta:
    "description lang=en": "A list of all components (charms) in the Content Cache operators project."
---

(reference_components)=

# Components

The Content Cache operators consist of two charms: `content-cache` and `content-cache-backends-config`.

## Content Cache

The [Content Cache](https://charmhub.io/content-cache) charm is the primary charm of the project.
It is a machine charm that manages an NGINX instance configured as a content cache.

## Content Cache Backends Config

```{warning}
This charm works with a WIP content-cache charm rewrite. This charm does not work with the current content-cache charm.
```

The [Content Cache Backends Config](https://charmhub.io/content-cache-backends-config) charm is a subordinate charm to the Content Cache charm. It provides the Content Cache charm with the configuration required to expose a set of backend services behind the caching capabilities of the Content Cache charm. 

