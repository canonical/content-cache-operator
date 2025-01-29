# Contributing

To make contributions to this charm, you'll need a working [development setup](https://juju.is/docs/sdk/dev-setup).

You can create an environment for development with `tox`:

```shell
tox devenv -e integration
source venv/bin/activate
```

## Testing

This project uses `tox` for managing test environments. There are some pre-configured environments
that can be used for linting and formatting code when you're preparing contributions to the charm:

```shell
tox run -e format        # update your code according to linting rules
tox run -e lint          # code style
tox run -e unit          # unit tests
tox run -e integration   # integration tests
tox                      # runs 'format', 'lint', and 'unit' environments
```

For integration tests, you can use the `--config-charm-file` to speed up tests:

```shell
tox run -e integration -- --config-charm-file=../content-cache-backends-config/content-cache-backends-config_amd64.charm
```

If you're iterating on integration tests, you can reuse existing resources with a command like the following one that will re-use the same model to run the basic tests:

```shell
tox run -e integration -- --charm-file=content-cache_amd64.charm --config-charm-file=../content-cache-backends-config/content-cache-backends-config_amd64.charm --keep-models --model test-cc --no-deploy -k test_basic
```

## Build the charm

Build the charm in this git repository using:

```shell
charmcraft pack
```

<!-- You may want to include any contribution/style guidelines in this document>
