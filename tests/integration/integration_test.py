import csv
import logging
import pathlib
import re
import socket
import textwrap

import pytest
import pytest_asyncio
import requests
import yaml

logger = logging.getLogger()


def supported_series():
    with open("metadata.yaml", encoding="utf-8") as f:
        metadata = yaml.safe_load(f)
    return metadata['series']


def series_version_mapping():
    reader = csv.DictReader(pathlib.Path("/usr/share/distro-info/ubuntu.csv").open())
    return {row["series"]: row["version"].split(" ")[0] for row in reader}


@pytest.fixture(params=supported_series(), scope="module", name="series")
def fixture_series(request):
    return request.param


@pytest_asyncio.fixture(scope="module", name="charm_file")
async def charm_file_fixture(ops_test, series, tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp(f"charm-{series}")
    charmcraft_file = pathlib.Path(".") / "charmcraft.yaml"
    charmcraft = yaml.safe_load(charmcraft_file.read_text())
    metadata_file = pathlib.Path(".") / "metadata.yaml"
    charm_name = yaml.safe_load(metadata_file.read_text())["name"]
    base_version = series_version_mapping()[series]
    base_index = None
    for idx, base in enumerate(charmcraft["bases"]):
        if base["run-on"][0]["channel"] == base_version:
            base_index = idx
    logger.info(f"build charm {charm_name}")
    cmd = ("charmcraft", "pack", "-p", pathlib.Path(".").absolute(), "--bases-index", str(base_index))
    logger.info(f"run command: {cmd}")
    return_code, stdout, stderr = await ops_test.run(*cmd, cwd=tmp_path)
    if return_code != 0:
        m = re.search(r"Failed to build charm.*full execution logs in '([^']+)'", stderr)
        if m:
            try:
                stderr = pathlib.Path(m.group(1)).read_text()
            except FileNotFoundError:
                logger.error(f"Failed to read full build log from {m.group(1)}")
        raise RuntimeError(f"Failed to build charm:\n{stderr}\n{stdout}")
    charm_file = next(tmp_path.glob(f"{charm_name}*.charm"))
    logger.info(f"built charm file: {charm_file}")
    return charm_file


@pytest_asyncio.fixture(scope="module", name="application")
async def fixture_application(ops_test, series, charm_file):
    def dns_lookup_ipv4(hostname):
        records = socket.getaddrinfo(hostname, 0)
        for record in records:
            if record[0] == socket.AddressFamily.AF_INET:
                return record[4][0]
        raise RuntimeError("No IPv4 DNS record for host: {}".format(hostname))

    application_name = "content-cache-{}".format(series)
    await ops_test.model.deploy(charm_file, series=series, application_name=application_name)
    # Get the IPv4 address for site to prevent some test environment IPv6 connectivity issues
    website_ip = dns_lookup_ipv4("archive.ubuntu.com")
    application = ops_test.model.applications[application_name]
    await application.set_config(
        {
            "sites": textwrap.dedent(
                """\
            archive.ubuntu.com:
              locations:
                /:
                  backends:
                    - {}:80""".format(
                    website_ip
                )
            )
        }
    )
    await ops_test.model.wait_for_idle()
    return application


@pytest.fixture(scope="module", name="update_config")
def fixture_update_config(ops_test, application):
    async def _update_config(config, assert_status="active"):
        await application.set_config(config)
        await ops_test.model.wait_for_idle()
        assert (
            application.status == assert_status
        ), "application status should be {} after applying {} configuration".format(assert_status, config)

    return _update_config


async def test_basic_functionality(application):
    unit = application.units[0]
    assert unit.workload_status == "active", "unit should be in active state"

    address = await unit.get_public_address()
    response = requests.get("http://{}".format(address), timeout=5)
    assert (
        response.status_code == 200 and "ubuntu" in response.text
    ), "content-cache server should respond with status code 200 and 'ubuntu' in content"
    ufw_status = await unit.ssh("sudo ufw status")
    assert "Status: inactive" in ufw_status, "ufw should be inactive with the default setting"


async def test_firewall_update(application, update_config):
    addresses = ["203.0.113.222", "203.0.113.0/25", "2001:db8::/32"]
    combinations = 2 ** len(addresses)
    # Iterate through every subset of the test IP set
    for i in range(combinations):
        # Since the default blocked_ips is empty, first tested blocked_ips should not be empty,
        # so we can test the non-empty -> empty situation
        i = (i + combinations // 2) % combinations
        blacklist = []
        for idx, address in enumerate(addresses):
            if (i >> idx) & 1:
                blacklist.append(address)
        await update_config({"blocked_ips": ",".join(blacklist)})
        unit = application.units[0]
        ufw_status = await unit.ssh("sudo ufw status")
        if not blacklist:
            assert "Status: inactive" in ufw_status, "ufw should be inactive when ip blacklist is empty"
        else:
            assert "Status: active" in ufw_status, "ufw should be active after blocked_ips being set to {}".format(
                blacklist
            )
        for address in addresses:
            if address in blacklist:
                assert (
                    re.search("DENY\\s+{}".format(address), ufw_status) is not None
                ), "address in the blacklist should be denied"
            else:
                assert address not in ufw_status, "address not in the blacklist should not be in the firewall rules"


async def test_firewall_misconfiguration(application, update_config):
    unit = application.units[0]
    await update_config({"blocked_ips": "203.0.113.1"})

    await update_config({"blocked_ips": "203.0.113.2,random"}, assert_status="blocked")
    ufw_status = await unit.ssh("sudo ufw status")
    assert (
        application.status == "blocked"
    ), "application should enter blocked state after receiving an illegal firewall config"
    assert (
        "random" in application.units[0].workload_status_message
    ), "the ip address causing trouble should be shown in the status message"
    assert "203.0.113.1" in ufw_status, "firewall state should not change when receiving a incorrect configuration"
    assert "203.0.113.2" not in ufw_status, "firewall update should follow all-or-none rule"

    await update_config({"blocked_ips": "203.0.113.3"})
    ufw_status = await unit.ssh("sudo ufw status")
    assert (
        application.status == "active"
        and "203.0.113.3" in ufw_status
        and all(ip not in ufw_status for ip in ("203.0.113.1", "203.0.113.2"))
    ), "application should return to normal after receiving an valid firewall config"
