import datetime
import os
import sys
import unittest

import freezegun

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
from lib import utils  # NOQA: E402


class TestLibUtils(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None

    def test_next_port_pair(self):
        self.assertEqual(utils.next_port_pair(0, 0),
                         (utils.BASE_CACHE_PORT, utils.BASE_BACKEND_PORT))
        cache_port = utils.BASE_CACHE_PORT
        backend_port = utils.BASE_BACKEND_PORT
        # Make sure next_port_pair() is incrementing.
        (cache_port, backend_port) = utils.next_port_pair(cache_port, backend_port)
        self.assertEqual((cache_port, backend_port),
                         (utils.BASE_CACHE_PORT + 1, utils.BASE_BACKEND_PORT + 1))
        (cache_port, backend_port) = utils.next_port_pair(cache_port, backend_port)
        self.assertEqual((cache_port, backend_port),
                         (utils.BASE_CACHE_PORT + 2, utils.BASE_BACKEND_PORT + 2))

        # Test last port still within range.
        max_ports = utils.BASE_BACKEND_PORT - utils.BASE_CACHE_PORT - 1
        (cache_port, backend_port) = utils.next_port_pair(utils.BASE_CACHE_PORT + max_ports - 1,
                                                          utils.BASE_BACKEND_PORT + max_ports - 1)
        self.assertEqual((cache_port, backend_port),
                         (utils.BASE_BACKEND_PORT - 1, utils.BASE_BACKEND_PORT + max_ports))

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
            utils.next_port_pair(0, utils.BACKEND_PORT_LIMIT,
                                 backend_port_limit=utils.BASE_BACKEND_PORT+10)

    def test_generate_nagios_check_name(self):
        self.assertEqual(utils.generate_nagios_check_name('site-1.local'), 'site_1_local')

    @freezegun.freeze_time("2019-03-22")
    def test_generate_token(self):
        signing_key = '2KmMh3/rx1LQRdjZIzto07Qaz/+LghG1c2G7od7FC/I='
        expiry_time = datetime.datetime.now() + datetime.timedelta(hours=1)
        expected = '1553176800_f8a6667ad994a013645eab53e9a757e65c206ee2'
        self.assertEqual(utils.generate_token(signing_key, '/', expiry_time), expected)

        expiry_time = datetime.datetime.now() + datetime.timedelta(days=1)
        expected = '1553259600_4cbf405bf08cee57eadcceb2ea98fc6767c6007b'
        self.assertEqual(utils.generate_token(signing_key, '/', expiry_time), expected)
