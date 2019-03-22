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

    @freezegun.freeze_time("2019-03-22")
    def test_generate_token(self):
        signing_key = '2KmMh3/rx1LQRdjZIzto07Qaz/+LghG1c2G7od7FC/I='
        expiry_time = datetime.datetime.now() + datetime.timedelta(hours=1)
        expected = '1553176800_f8a6667ad994a013645eab53e9a757e65c206ee2'
        self.assertEqual(utils.generate_token(signing_key, '/', expiry_time), expected)

        expiry_time = datetime.datetime.now() + datetime.timedelta(days=1)
        expected = '1553259600_4cbf405bf08cee57eadcceb2ea98fc6767c6007b'
        self.assertEqual(utils.generate_token(signing_key, '/', expiry_time), expected)
