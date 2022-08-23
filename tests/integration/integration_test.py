import re
import socket
import textwrap
import yaml
import pytest
import requests
import pytest_asyncio


def supported_series():
    with open("metadata.yaml", encoding="utf-8") as f:
        metadata = yaml.safe_load(f)
    return metadata['series']


@pytest.fixture(params=supported_series(), scope="module", name="series")
def fixture_series(request):
    return request.param


@pytest_asyncio.fixture(scope="module", name="application")
async def fixture_application(ops_test, series):
    def dns_lookup_ipv4(hostname):
        records = socket.getaddrinfo(hostname, 0)
        for record in records:
            if record[0] == socket.AddressFamily.AF_INET:
                return record[4][0]
        raise RuntimeError("No IPv4 DNS record for host: {}".format(hostname))

    my_charm = await ops_test.build_charm(".")
    application_name = "content-cache-{}".format(series)
    await ops_test.model.deploy(my_charm, series=series, application_name=application_name)
    # Get the IPv4 address for site to prevent some test environment IPv6 connectivity issues
    website_ip = dns_lookup_ipv4("archive.ubuntu.com")
    application = ops_test.model.applications[application_name]
    await application.set_config({
        "sites": textwrap.dedent("""\
            archive.ubuntu.com:
              locations:
                /:
                  backends:
                    - {}:80""".format(website_ip))
    })
    await ops_test.model.wait_for_idle()
    return application


@pytest.fixture(scope="module", name="update_config")
def fixture_update_config(ops_test, application):
    async def _update_config(config):
        await application.set_config(config)
        await ops_test.model.wait_for_idle()

    return _update_config


async def test_basic_functionality(application):
    unit = application.units[0]
    assert unit.workload_status == "active", \
        "unit should be in active state"

    address = await unit.get_public_address()
    response = requests.get("http://{}".format(address), timeout=5)
    assert response.status_code == 200 and "ubuntu" in response.text, \
        "content cache server should response with correct content"
    ufw_status = await unit.ssh("sudo ufw status")
    assert "Status: active" in ufw_status and "DENY" not in ufw_status, \
        "ufw should be ready and empty"


async def test_firewall_update(application, update_config):
    addresses = ["203.0.113.222", "203.0.113.0/25", "2001:db8::/32"]
    # iterate through every subset of the test IP set
    for i in range(2 ** len(addresses)):
        blacklist = []
        for idx, address in enumerate(addresses):
            if (i >> idx) & 1:
                blacklist.append(address)
        await update_config({"blocked_ips": ",".join(blacklist)})
        unit = application.units[0]
        ufw_status = await unit.ssh("sudo ufw status")
        for address in addresses:
            if address in blacklist:
                assert re.search("DENY\\s+{}".format(address), ufw_status) is not None, \
                    "address in the blacklist should be denied"
            else:
                assert address not in ufw_status, \
                    "address not in the blacklist should not be in the firewall rules"


async def test_firewall_misconfiguration(application, update_config):
    unit = application.units[0]
    await update_config({"blocked_ips": "203.0.113.1"})

    await update_config({"blocked_ips": "203.0.113.2,random"})
    ufw_status = await unit.ssh("sudo ufw status")
    assert application.status == "blocked", \
        "application should enter blocked state after receiving an illegal firewall config"
    assert "random" in application.units[0].workload_status_message, \
        "the ip address causing trouble should be shown in the status message"
    assert "203.0.113.1" in ufw_status, \
        "firewall state should not change when receiving a incorrect configuration"
    assert "203.0.113.2" not in ufw_status, \
        "firewall update should follow all-or-none rule"

    await update_config({"blocked_ips": "203.0.113.3"})
    ufw_status = await unit.ssh("sudo ufw status")
    assert application.status == "active" and \
           "203.0.113.3" in ufw_status and \
           all(ip not in ufw_status for ip in ("203.0.113.1", "203.0.113.2")), \
        "application should return to normal after receiving an valid firewall config"
