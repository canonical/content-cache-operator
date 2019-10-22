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
        expiry_time = datetime.datetime.now() + datetime.timedelta(hours=1)
        want = '1553216400_cd3920a15f1d58b9953ef7a8e7e9c46d4522a5e9'
        self.assertEqual(utils.generate_token(signing_key, '/', expiry_time), want)

        expiry_time = datetime.datetime.now() + datetime.timedelta(days=1)
        want = '1553299200_d5257bb9f1e5e27065f2e7c986ca8c95f4cc3680'
        self.assertEqual(utils.generate_token(signing_key, '/', expiry_time), want)

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
