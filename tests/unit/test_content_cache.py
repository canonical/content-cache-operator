import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

# We also need to mock up charms.layer so we can run unit tests without having
# to build the charm and pull in layers such as layer-status.
sys.modules['charms.layer'] = mock.MagicMock()

from charms.layer import status  # NOQA: E402
# Add path to where our reactive layer lives and import.
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
from reactive import content_cache  # NOQA: E402


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.tmpdir = tempfile.mkdtemp(prefix='charm-unittests-')
        self.addCleanup(shutil.rmtree, self.tmpdir)

        self.charm_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

        patcher = mock.patch('charmhelpers.core.hookenv.log')
        self.mock_log = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_log.return_value = ''

        patcher = mock.patch('charmhelpers.core.hookenv.charm_dir')
        self.mock_charm_dir = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_charm_dir.return_value = self.charm_dir

        patcher = mock.patch('charmhelpers.core.hookenv.local_unit')
        self.mock_local_unit = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_local_unit.return_value = 'mock-content-cache/0'

        patcher = mock.patch('charmhelpers.core.hookenv.config')
        self.mock_config = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_config.return_value = {}

        patcher = mock.patch('multiprocessing.cpu_count')
        self.mock_cpu_count = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_cpu_count.return_value = 4

    @mock.patch('charms.reactive.clear_flag')
    def test_hook_upgrade_charm_flags(self, clear_flag):
        '''Test correct flags set via upgrade-charm hook'''
        status.maintenance.reset_mock()
        content_cache.upgrade_charm()
        self.assertFalse(status.maintenance.assert_called())
        expected = [mock.call('content_cache.active'),
                    mock.call('content_cache.installed'),
                    mock.call('content_cache.haproxy.configured'),
                    mock.call('content_cache.nginx.configured')]
        self.assertFalse(clear_flag.assert_has_calls(expected, any_order=True))

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    def test_hook_install_flags(self, set_flag, clear_flag):
        '''Test correct flags are set via install charm hook'''
        content_cache.install()
        expected = [mock.call('content_cache.installed')]
        self.assertFalse(set_flag.assert_has_calls(expected, any_order=True))

        expected = [mock.call('content_cache.active'),
                    mock.call('content_cache.haproxy.configured'),
                    mock.call('content_cache.nginx.configured')]
        self.assertFalse(clear_flag.assert_has_calls(expected, any_order=True))

    @mock.patch('charms.reactive.clear_flag')
    def test_hook_config_changed_flags(self, clear_flag):
        '''Test correct flags are set via config-changed charm hook'''
        content_cache.config_changed()
        expected = [mock.call('content_cache.haproxy.configured'),
                    mock.call('content_cache.nginx.configured')]
        self.assertFalse(clear_flag.assert_has_calls(expected, any_order=True))

    @mock.patch('charms.reactive.set_flag')
    def test_hook_set_active(self, set_flag):
        status.active.reset_mock()
        content_cache.set_active()
        self.assertFalse(status.active.assert_called())
        self.assertFalse(set_flag.assert_called_once_with('content_cache.active'))

    @mock.patch('charmhelpers.core.host.service_running')
    @mock.patch('charmhelpers.core.host.service_restart')
    @mock.patch('charmhelpers.core.host.service_start')
    def test_service_start_or_restart_running(self, service_start, service_restart, service_running):
        '''Test service restarted when already running'''
        service_running.return_value = True
        status.active.reset_mock()
        content_cache.service_start_or_restart('someservice')
        self.assertFalse(status.maintenance.assert_called())
        self.assertFalse(service_start.assert_not_called())
        self.assertFalse(service_restart.assert_called_once_with('someservice'))

    @mock.patch('charmhelpers.core.host.service_running')
    @mock.patch('charmhelpers.core.host.service_restart')
    @mock.patch('charmhelpers.core.host.service_start')
    def test_service_start_or_restart_stopped(self, service_start, service_restart, service_running):
        '''Test service started up when not running/stopped'''
        service_running.return_value = False
        status.active.reset_mock()
        content_cache.service_start_or_restart('someservice')
        self.assertFalse(status.maintenance.assert_called())
        self.assertFalse(service_start.assert_called_once_with('someservice'))
        self.assertFalse(service_restart.assert_not_called())

    @mock.patch('charms.reactive.clear_flag')
    def test_configure_nginx_no_sites(self, clear_flag):
        '''Test correct flags are set when no sites defined to configure Nginx'''
        status.blocked.reset_mock()
        content_cache.configure_nginx()
        self.assertFalse(status.blocked.assert_called())
        self.assertFalse(clear_flag.assert_called_once_with('content_cache.active'))

    @mock.patch('reactive.content_cache.service_start_or_restart')
    def test_configure_nginx_sites(self, service_start_or_restart):
        '''Test configuration of Nginx sites'''
        with open('tests/unit/files/nginx_config_test_config.txt', 'r', encoding='utf-8') as f:
            ngx_config = f.read()
        self.mock_config.return_value = {'sites': ngx_config}

        with mock.patch('lib.nginx.NginxConf.sites_path', new_callable=mock.PropertyMock) as mock_site_path:
            mock_site_path.return_value = os.path.join(self.tmpdir, 'sites-available')
            # sites-available and sites-enabled won't exist in our temp dir
            os.mkdir(os.path.join(self.tmpdir, 'sites-available'))
            os.mkdir(os.path.join(self.tmpdir, 'sites-enabled'))
            content_cache.configure_nginx()
            self.assertFalse(service_start_or_restart.assert_called_once_with('nginx'))

            # Re-run with same set of sites, no change so shouldn't need to restart Nginx
            service_start_or_restart.reset_mock()
            content_cache.configure_nginx()
            self.assertFalse(service_start_or_restart.assert_not_called())

    @mock.patch('charms.reactive.clear_flag')
    def test_configure_haproxy_no_sites(self, clear_flag):
        status.blocked.reset_mock()
        content_cache.configure_haproxy()
        self.assertFalse(status.blocked.assert_called())
        self.assertFalse(clear_flag.assert_called_once_with('content_cache.active'))

    @mock.patch('reactive.content_cache.service_start_or_restart')
    def test_configure_haproxy_sites(self, service_start_or_restart):
        with open('tests/unit/files/config_test_config.txt', 'r', encoding='utf-8') as f:
            ngx_config = f.read()
        self.mock_config.return_value = {'sites': ngx_config}

        with open('tests/unit/files/content_cache_rendered_haproxy_test_output.txt', 'r', encoding='utf-8') as f:
            expected = f.read()
        with mock.patch('lib.haproxy.HAProxyConf.conf_file', new_callable=mock.PropertyMock) as mock_conf_file:
            mock_conf_file.return_value = os.path.join(self.tmpdir, 'haproxy.cfg')
            content_cache.configure_haproxy()
            with open(os.path.join(self.tmpdir, 'haproxy.cfg'), 'r', encoding='utf-8') as f:
                current = f.read()
            self.assertEqual(expected, current)
            self.assertFalse(service_start_or_restart.assert_called_with('haproxy'))

            # Again, this time should be no change so no need to restart HAProxy
            service_start_or_restart.reset_mock()
            content_cache.configure_haproxy()
            self.assertFalse(service_start_or_restart.assert_not_called())

    def test_next_port_pair(self):
        self.assertEqual(content_cache.next_port_pair(0, 0),
                         (content_cache.BASE_CACHE_PORT, content_cache.BASE_BACKEND_PORT))
        cache_port = content_cache.BASE_CACHE_PORT
        backend_port = content_cache.BASE_BACKEND_PORT
        # Make sure next_port_pair() is incrementing.
        (cache_port, backend_port) = content_cache.next_port_pair(cache_port, backend_port)
        self.assertEqual((cache_port, backend_port),
                         (content_cache.BASE_CACHE_PORT + 1, content_cache.BASE_BACKEND_PORT + 1))
        (cache_port, backend_port) = content_cache.next_port_pair(cache_port, backend_port)
        self.assertEqual((cache_port, backend_port),
                         (content_cache.BASE_CACHE_PORT + 2, content_cache.BASE_BACKEND_PORT + 2))

        # Test last port still within range.
        max_ports = content_cache.BASE_BACKEND_PORT - content_cache.BASE_CACHE_PORT - 1
        (cache_port, backend_port) = content_cache.next_port_pair(content_cache.BASE_CACHE_PORT + max_ports - 1,
                                                                  content_cache.BASE_BACKEND_PORT + max_ports - 1)
        self.assertEqual((cache_port, backend_port),
                         (content_cache.BASE_BACKEND_PORT - 1, content_cache.BASE_BACKEND_PORT + max_ports))

    def test_next_port_pair_out_of_range(self):
        with self.assertRaises(content_cache.InvalidPortError):
            content_cache.next_port_pair(1024, 0)
        with self.assertRaises(content_cache.InvalidPortError):
            content_cache.next_port_pair(content_cache.BASE_CACHE_PORT - 2, 0)

        max_ports = content_cache.BASE_BACKEND_PORT - content_cache.BASE_CACHE_PORT - 1
        with self.assertRaises(content_cache.InvalidPortError):
            content_cache.next_port_pair(0, content_cache.BASE_BACKEND_PORT + max_ports)
        with self.assertRaises(content_cache.InvalidPortError):
            content_cache.next_port_pair(0, content_cache.BACKEND_PORT_LIMIT)

        # Absolute max. based on net.ipv4.ip_local_port_range defaults
        with self.assertRaises(content_cache.InvalidPortError):
            content_cache.next_port_pair(0, content_cache.BACKEND_PORT_LIMIT,
                                         backend_port_limit=content_cache.BASE_BACKEND_PORT+10)


if __name__ == '__main__':
    unittest.main()
