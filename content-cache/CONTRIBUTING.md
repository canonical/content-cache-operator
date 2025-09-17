# How to contribute

Please read the [main contributing guide](/CONTRIBUTING.md) first.

## Develop

To make contributions to this charm, you'll need a working
[development setup](https://documentation.ubuntu.com/juju/latest/user/howto/manage-your-deployment/manage-your-deployment-environment/).

The code for this charm can be downloaded as follows:

```
git clone https://github.com/canonical/content-cache-operator/
```

You can create an environment for development with `python3-venv`:

```bash
sudo apt install python3-venv
python3 -m venv venv
source venv/bin/activate
pip install tox
```

Install `tox` inside the virtual environment for testing.

### Test

This project uses `tox` for managing test environments. There are some pre-configured environments
that can be used for linting and formatting code when you're preparing contributions to the charm:

* ``tox``: Executes all of the basic checks and tests (``lint``, ``unit``, ``static``, and ``coverage-report``).
* ``tox -e fmt``: Runs formatting using ``black`` and ``isort``.
* ``tox -e lint``: Runs a range of static code analysis to check the code.
* ``tox -e static``: Runs other checks such as ``bandit`` for security issues.
* ``tox run -e integration``: Runs integration tests.
* `tox -e unit`: Runs the unit tests.

For integration tests, you can use the `--config-charm-file` to speed up tests:

```shell
tox run -e integration -- --config-charm-file=../content-cache-backends-config/content-cache-backends-config_amd64.charm
```

If you're iterating on integration tests, you can reuse existing resources with a command like the following one that will reuse the same model to run the basic tests:

```shell
tox run -e integration -- --charm-file=content-cache_amd64.charm --config-charm-file=../content-cache-backends-config/content-cache-backends-config_amd64.charm --keep-models --model test-cc --no-deploy -k test_basic
```

### Build the charm

Build the charm in this git repository using:

```shell
charmcraft pack
```

### Deploy

```bash
# Create a model
juju add-model charm-dev
# Enable DEBUG logging
juju model-config logging-config="<root>=INFO;unit=DEBUG"
# Deploy the charm
juju deploy ./content-cache_ubuntu-24.04-amd64.charm 
```
