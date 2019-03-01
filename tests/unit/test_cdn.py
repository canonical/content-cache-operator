import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.modules['charms.apt'] = mock.MagicMock()
from charms import apt  # NOQA: E402

# Add path to where our reactive layer lives and import.
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
from reactive.cdn import (
    install,
    config_changed,
    upgrade_charm,
)  # NOQA: E402


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='charm-unittests-')

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_hook_install(self):
        install()
        expected = [mock.call.queue_install(['haproxy', 'nginx']),
                    mock.call.install_queued()]
        self.assertEqual(apt.method_calls, expected)

    def test_hook_config_changed(self):
        config_changed()
        self.assertTrue(True)

    def test_hook_upgrade_charm(self):
        upgrade_charm()
        self.assertTrue(True)


if __name__ == '__main__':
    unittest.main()
