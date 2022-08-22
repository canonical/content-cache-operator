import os
import sys
import textwrap
import unittest
from ipaddress import IPv4Network, IPv6Network

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
from reactive import content_cache


class TestFireWallConfig(unittest.TestCase):
    def test_parse_default_firewall_config(self):
        self.assertEqual(
            content_cache.parse_ip_blocklist_config(""),
            [],
            "default config should be an empty blocklist"
        )

    def test_parse_firewall_config(self):
        config = textwrap.dedent("""\
        10.0.1.1,10.0.1.2 # comments 10.0.3.4,,
        
        10.0.2.1/32,
        10.0.2.0/24,10.0.2.128/25,
        # comments
        
        ::ffff:0:0/96,::ffff:255.255.255.255
        """)
        parsed_result = content_cache.parse_ip_blocklist_config(config)
        self.assertSetEqual(
            set(parsed_result),
            {
                IPv4Network("10.0.1.1"),
                IPv4Network("10.0.1.2"),
                IPv4Network("10.0.2.1"),
                IPv4Network("10.0.2.0/24"),
                IPv4Network("10.0.2.128/25"),
                IPv6Network("::ffff:0:0/96"),
                IPv6Network("::ffff:255.255.255.255")
            },
            "complicated config should be parsed correctly"
        )
