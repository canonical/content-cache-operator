# cache-config

Shared models and relation-data helpers for the `cache-config` interface
(`content-cache-config` in `charmcraft.yaml`/`metadata.yaml` terms), used between:

- requirer charms (e.g. `content-cache-backends-config`, `ingress-configurator`) that
  configure a `content-cache` deployment with backend origins, healthcheck parameters,
  and caching rules, and read back the URL `content-cache` serves on; and
- the `content-cache` provider charm itself, which validates the requirer's
  configuration and publishes the `cache-backend` URL per relation.

This package is the single source of truth for the interface's relation data schema and
validation rules, so that every charm speaking `cache-config` rejects/accepts exactly the
same values.

## Usage

### In this monorepo (`content-cache`, `content-cache-backends-config`)

Each charm's `lib/cache_config` is a symlink to `../../libs/cache_config/src/cache_config`
(this directory), so the package is importable as `import cache_config` without any
extra build step: charms already add `lib/` to `PYTHONPATH` at dispatch time.

### From another repository (e.g. `ingress-configurator-operator`)

Add it as a git dependency pinned to a tag or commit, for example in `pyproject.toml`:

```toml
dependencies = [
  "cache-config @ git+https://github.com/canonical/content-cache-operator@main#subdirectory=libs/cache_config",
]
```

`git` must be available in the charm's build environment (add it to
`parts.charm.build-packages` in `charmcraft.yaml`).
