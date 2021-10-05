import collections
import datetime
import os
import sys
import unittest
from unittest import mock

import freezegun

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
from lib import utils  # NOQA: E402


class TestLibUtils(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None

    def test_next_port_pair(self):
        self.assertEqual(utils.next_port_pair(0, 0), (utils.BASE_CACHE_PORT, utils.BASE_BACKEND_PORT))
        cache_port = utils.BASE_CACHE_PORT
        backend_port = utils.BASE_BACKEND_PORT
        # Make sure next_port_pair() is incrementing.
        (cache_port, backend_port) = utils.next_port_pair(cache_port, backend_port)
        self.assertEqual((cache_port, backend_port), (utils.BASE_CACHE_PORT + 1, utils.BASE_BACKEND_PORT + 1))
        (cache_port, backend_port) = utils.next_port_pair(cache_port, backend_port)
        self.assertEqual((cache_port, backend_port), (utils.BASE_CACHE_PORT + 2, utils.BASE_BACKEND_PORT + 2))

        # Test last port still within range.
        max_ports = utils.BASE_BACKEND_PORT - utils.BASE_CACHE_PORT - 1
        (cache_port, backend_port) = utils.next_port_pair(
            utils.BASE_CACHE_PORT + max_ports - 1, utils.BASE_BACKEND_PORT + max_ports - 1
        )
        self.assertEqual((cache_port, backend_port), (utils.BASE_BACKEND_PORT - 1, utils.BASE_BACKEND_PORT + max_ports))

        # Blacklisted ports
        self.assertEqual(
            utils.next_port_pair(0, 0, blacklist_ports=[utils.BASE_CACHE_PORT, utils.BASE_BACKEND_PORT]),
            (utils.BASE_CACHE_PORT + 1, utils.BASE_BACKEND_PORT + 1),
        )

    def test_next_port_pair_out_of_range(self):
        with self.assertRaises(utils.InvalidPortError):
            utils.next_port_pair(1024, 0)
        with self.assertRaises(utils.InvalidPortError):
            utils.next_port_pair(utils.BASE_CACHE_PORT - 2, 0)

        max_ports = utils.BASE_BACKEND_PORT - utils.BASE_CACHE_PORT - 1
        with self.assertRaises(utils.InvalidPortError):
            utils.next_port_pair(0, utils.BASE_BACKEND_PORT + max_ports)
        with self.assertRaises(utils.InvalidPortError):
            utils.next_port_pair(0, utils.BACKEND_PORT_LIMIT)

        # Absolute max. based on net.ipv4.ip_local_port_range defaults
        with self.assertRaises(utils.InvalidPortError):
            utils.next_port_pair(0, utils.BACKEND_PORT_LIMIT, backend_port_limit=utils.BASE_BACKEND_PORT + 10)

    def test_generate_nagios_check_name(self):
        self.assertEqual(utils.generate_nagios_check_name('site-1.local'), 'site_1_local')
        self.assertEqual(utils.generate_nagios_check_name('site-1.local_'), 'site_1_local')
        self.assertEqual(utils.generate_nagios_check_name('site-1.local__'), 'site_1_local')
        self.assertEqual(utils.generate_nagios_check_name('site-1.local', 'site', '/'), 'site_site_1_local')
        self.assertEqual(
            utils.generate_nagios_check_name('site-1.local', 'site', '/somepath'), 'site_site_1_local_somepath'
        )

    @freezegun.freeze_time("2019-03-22", tz_offset=0)
    def test_generate_token(self):
        signing_key = '2KmMh3/rx1LQRdjZIzto07Qaz/+LghG1c2G7od7FC/I='
        want = '1553216400_cd3920a15f1d58b9953ef7a8e7e9c46d4522a5e9'
        expiry_time = datetime.datetime.now() + datetime.timedelta(hours=1)
        self.assertEqual(utils.generate_token(signing_key, '/', expiry_time), want)

        want = '1553299200_d5257bb9f1e5e27065f2e7c986ca8c95f4cc3680'
        expiry_time = datetime.datetime.now() + datetime.timedelta(days=1)
        self.assertEqual(utils.generate_token(signing_key, '/', expiry_time), want)

        want = '1574467200_7087ba9298954ff8759409f523f890e400748b30'
        with freezegun.freeze_time("2019-11-22", tz_offset=0):
            expiry_time = datetime.datetime.now() + datetime.timedelta(days=1)
            self.assertEqual(utils.generate_token(signing_key, '/', expiry_time), want)

        want = '1921622400_e47bcc2a32bcf33bd510579e98102a5da12881d3'
        with freezegun.freeze_time("2020-11-22", tz_offset=0):
            expiry_time = datetime.datetime.now() + datetime.timedelta(days=3653)
            self.assertEqual(utils.generate_token(signing_key, '/', expiry_time), want)

    def test_never_expires_time(self):
        with freezegun.freeze_time("2020-02-04", tz_offset=0):
            self.assertEqual(utils.never_expires_time(), datetime.datetime(2030, 1, 1, 0, 0))

        with freezegun.freeze_time("2025-11-22", tz_offset=0):
            self.assertEqual(utils.never_expires_time(), datetime.datetime(2035, 1, 2, 0, 0))

        with freezegun.freeze_time("1990-03-22", tz_offset=0):
            self.assertEqual(utils.never_expires_time(), datetime.datetime(2000, 1, 2, 0, 0))

    def test_generate_uri(self):
        self.assertEqual(utils.generate_uri('localhost'), 'http://localhost:80')
        self.assertEqual(utils.generate_uri('localhost', 8080), 'http://localhost:8080')
        self.assertEqual(utils.generate_uri('localhost', path='mypath'), 'http://localhost:80/mypath')
        self.assertEqual(utils.generate_uri('localhost', path='/mypath'), 'http://localhost:80/mypath')
        self.assertEqual(utils.generate_uri('10.0.0.1', path='/mypath'), 'http://10.0.0.1:80/mypath')

    @mock.patch('shutil.disk_usage')
    def test_cache_max_size(self, disk_usage):
        mbytes = 1024 * 1024
        gbytes = mbytes * 1024

        disk_total = 240 * gbytes
        disk_usage.return_value = (disk_total, 0, 0)
        self.assertEqual(utils.cache_max_size('/srv'), '180g')
        self.assertEqual(utils.cache_max_size('/srv', percent=50), '120g')
        disk_usage.return_value = (0, 0, 0)
        self.assertEqual(utils.cache_max_size('/srv'), '1g')

    def test_ip_addr_port_split_ipv6(self):
        self.assertEqual(utils.ip_addr_port_split('[::]:80'), ('::', 80))
        self.assertEqual(utils.ip_addr_port_split('[fe80::1]:443'), ('fe80::1', 443))

        # Ensure IPv6 addresses are enclosed in square brackets - '[' and ']'.
        with self.assertRaises(utils.InvalidAddressPortError):
            utils.ip_addr_port_split(':::80')
        with self.assertRaises(utils.InvalidAddressPortError):
            utils.ip_addr_port_split('fe80::1:443')

        # Invalid IPv6 address.
        with self.assertRaises(utils.InvalidAddressPortError):
            utils.ip_addr_port_split('[zz80::1]:443')
        # Invalid port.
        with self.assertRaises(utils.InvalidAddressPortError):
            utils.ip_addr_port_split('[fe80::1]:65536')

    def test_ip_addr_port_split_ipv4(self):
        self.assertEqual(utils.ip_addr_port_split('0.0.0.0:80'), ('0.0.0.0', 80))
        self.assertEqual(utils.ip_addr_port_split('10.0.0.1:443'), ('10.0.0.1', 443))

        # Invalid IPv4 address.
        with self.assertRaises(utils.InvalidAddressPortError):
            utils.ip_addr_port_split('10.0.0.256:443')
        with self.assertRaises(utils.InvalidAddressPortError):
            utils.ip_addr_port_split('dsafds:80')
        # Invalid port.
        with self.assertRaises(utils.InvalidAddressPortError):
            utils.ip_addr_port_split('10.0.0.1:65536')

    def test_tls_cipher_suites(self):
        tls_cipher_suites = 'ECDH+AESGCM:ECDH+AES256:ECDH+AES128:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS'
        self.assertEqual(utils.tls_cipher_suites(tls_cipher_suites), tls_cipher_suites)

        tls_cipher_suites = 'SomeInvalidOpenSSLCipherString'
        with self.assertRaises(utils.InvalidTLSCiphersError):
            utils.tls_cipher_suites(tls_cipher_suites)

        tls_cipher_suites = '--help'
        with self.assertRaises(utils.InvalidTLSCiphersError):
            utils.tls_cipher_suites(tls_cipher_suites)

    def test_logrotate(self):
        with open('tests/unit/files/haproxy-dateext-logrotate.conf') as f:
            self.assertEqual(utils.logrotate(retention=52, path='tests/unit/files/haproxy-logrotate.conf'), f.read())
        with open('tests/unit/files/nginx-dateext-logrotate.conf') as f:
            self.assertEqual(utils.logrotate(retention=14, path='tests/unit/files/nginx-logrotate.conf'), f.read())

        # Test dateext removal.
        with open('tests/unit/files/nginx-logrotate.conf') as f:
            self.assertEqual(
                utils.logrotate(retention=14, dateext=False, path='tests/unit/files/nginx-dateext-logrotate.conf'),
                f.read(),
            )

        # Test when config file doesn't exist.
        self.assertEqual(utils.logrotate(retention=14, path='tests/unit/files/some-file-that-doesnt-exist'), None)

    def test_process_rlimits(self):
        # Read current Max open files from PID 1 and make sure
        # utils.process_rlimits() returns the same.
        with open('/proc/1/limits') as f:
            for line in f:
                if line.startswith('Max open files'):
                    limit = str(line.split()[4])
        self.assertEqual(limit, utils.process_rlimits(1, 'NOFILE'))
        self.assertEqual(limit, utils.process_rlimits(1, 'NOFILE', None))
        self.assertEqual(limit, utils.process_rlimits(1, 'NOFILE', 'tests/unit/files/limits.txt'))

        self.assertEqual(None, utils.process_rlimits(1, 'NOFILE', 'tests/unit/files/test_file.txt'))
        self.assertEqual(None, utils.process_rlimits(1, 'NOFILE', 'tests/unit/files/limits-file-does-not-exist.txt'))

        self.assertEqual(None, utils.process_rlimits(1, 'NOMATCH'))

    def test_dns_servers(self):
        want = ['127.0.0.53']
        self.assertEqual(want, utils.dns_servers('tests/unit/files/resolv.conf'))
        want = ['127.0.0.53', '127.0.0.153']
        self.assertEqual(want, utils.dns_servers('tests/unit/files/resolv.conf2'))
        want = []
        self.assertEqual(want, utils.dns_servers('tests/unit/files/resolv.conf-none'))

    def test_package_version(self):
        self.assertTrue(int(utils.package_version('apt').split('.')[0]) > 1)

        with mock.patch('subprocess.check_output') as check_output:
            check_output.return_value = '1.8.8-1ubuntu0.10'
            self.assertEqual(utils.package_version('haproxy'), '1.8.8-1ubuntu0.10')

            check_output.return_value = '2.0.13-2'
            self.assertEqual(utils.package_version('haproxy'), '2.0.13-2')

            check_output.return_value = ''
            self.assertEqual(utils.package_version('haproxy'), None)

        self.assertEqual(utils.package_version('some-package-doesnt-exist'), None)

    def test_select_tcp_congestion_control(self):
        sysctl_tcp_cc_path = 'some-file-does-not-exist'
        preferred = ['bbr']
        want = None
        self.assertEqual(utils.select_tcp_congestion_control(preferred, sysctl_tcp_cc_path), want)

        sysctl_tcp_cc_path = 'tests/unit/files/sysctl_net_tcp_congestion_control.txt'
        preferred = ['bbr2', 'bbr']
        want = 'bbr'
        self.assertEqual(utils.select_tcp_congestion_control(preferred, sysctl_tcp_cc_path), want)

        sysctl_tcp_cc_path = 'tests/unit/files/sysctl_net_tcp_congestion_control_bbr2.txt'
        preferred = ['bbr2', 'bbr']
        want = 'bbr2'
        self.assertEqual(utils.select_tcp_congestion_control(preferred, sysctl_tcp_cc_path), want)

        sysctl_tcp_cc_path = 'tests/unit/files/sysctl_net_tcp_congestion_control_no_bbr.txt'
        preferred = ['bbr2', 'bbr']
        want = None
        self.assertEqual(utils.select_tcp_congestion_control(preferred, sysctl_tcp_cc_path), want)

    @mock.patch('psutil.virtual_memory')
    def test_tune_tcp_mem(self, virtual_memory):
        svmem = collections.namedtuple('svmem', ['total'])

        svmem.total = 541071241216
        virtual_memory.return_value = svmem
        want = '18546484 24728646 37092969'
        self.assertEqual(utils.tune_tcp_mem(), want)

        svmem.total = 8230563840
        virtual_memory.return_value = svmem
        want = '282121 376162 564243'
        self.assertEqual(utils.tune_tcp_mem(), want)

        sysctl_tcp_mem_path = 'some-file-does-not-exist'
        want = None
        self.assertEqual(utils.tune_tcp_mem(sysctl_tcp_mem_path), want)
