import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

# We also need to mock up charms.layer so we can run unit tests without having
# to build the charm and pull in layers such as layer-status.
sys.modules['charms.apt'] = mock.MagicMock()
sys.modules['charms.layer'] = mock.MagicMock()

from charms import apt  # NOQA: E402
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
        self.mock_config.return_value = {'nagios_context': 'juju'}

        patcher = mock.patch('multiprocessing.cpu_count')
        self.mock_cpu_count = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_cpu_count.return_value = 4

        status.active.reset_mock()
        status.blocked.reset_mock()
        status.maintenance.reset_mock()

    @mock.patch('charms.reactive.clear_flag')
    def test_hook_upgrade_charm_flags(self, clear_flag):
        '''Test correct flags set via upgrade-charm hook'''
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
        content_cache.set_active()
        self.assertFalse(status.active.assert_called())
        self.assertFalse(set_flag.assert_called_once_with('content_cache.active'))

    @mock.patch('charmhelpers.core.host.service_running')
    @mock.patch('charmhelpers.core.host.service_restart')
    @mock.patch('charmhelpers.core.host.service_start')
    def test_service_start_or_restart_running(self, service_start, service_restart, service_running):
        '''Test service restarted when already running'''
        service_running.return_value = True
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
        content_cache.service_start_or_restart('someservice')
        self.assertFalse(status.maintenance.assert_called())
        self.assertFalse(service_start.assert_called_once_with('someservice'))
        self.assertFalse(service_restart.assert_not_called())

    @mock.patch('charms.reactive.clear_flag')
    def test_configure_nginx_no_sites(self, clear_flag):
        '''Test correct flags are set when no sites defined to configure Nginx'''
        content_cache.configure_nginx()
        self.assertFalse(status.blocked.assert_called())
        self.assertFalse(clear_flag.assert_called_once_with('content_cache.active'))

    @mock.patch('reactive.content_cache.service_start_or_restart')
    def test_configure_nginx_sites(self, service_start_or_restart):
        '''Test configuration of Nginx sites'''
        with open('tests/unit/files/config_test_config.txt', 'r', encoding='utf-8') as f:
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

            for site in ['site1.local', 'site2.local', 'site3.local']:
                with open('tests/unit/files/nginx_config_rendered_test_output-{}.txt'.format(site),
                          'r', encoding='utf-8') as f:
                    expected = f.read()
                with open(os.path.join(self.tmpdir, 'sites-available/{}.conf'.format(site)),
                          'r', encoding='utf-8') as f:
                    current = f.read()
                self.assertEqual(expected, current)

    def test_configure_nginx_sites_signed_url(self):
        with open('tests/unit/files/config_test_config_signed_url.txt', 'r', encoding='utf-8') as f:
            ngx_config = f.read()
        self.mock_config.return_value = {
            'sites': ngx_config,
            'signed-url-hmac-key': '2PNKDi6xkqUFp/yZvI/sFBi3lknbnDLFDvaBCvZDQW0=',
        }

        with mock.patch('lib.nginx.NginxConf.sites_path', new_callable=mock.PropertyMock) as mock_site_path:
            mock_site_path.return_value = os.path.join(self.tmpdir, 'sites-available')
            # sites-available and sites-enabled won't exist in our temp dir
            os.mkdir(os.path.join(self.tmpdir, 'sites-available'))
            os.mkdir(os.path.join(self.tmpdir, 'sites-enabled'))
            content_cache.configure_nginx()

            for site in ['site1.local']:
                with open('tests/unit/files/nginx_config_rendered_test_output-{}_signed_url.txt'.format(site),
                          'r', encoding='utf-8') as f:
                    expected = f.read()
                with open(os.path.join(self.tmpdir, 'sites-available/{}.conf'.format(site)),
                          'r', encoding='utf-8') as f:
                    current = f.read()
                self.assertEqual(expected, current)

    @mock.patch('charms.reactive.clear_flag')
    def test_configure_haproxy_no_sites(self, clear_flag):
        content_cache.configure_haproxy()
        self.assertFalse(status.blocked.assert_called())
        self.assertFalse(clear_flag.assert_called_once_with('content_cache.active'))

    @mock.patch('reactive.content_cache.service_start_or_restart')
    def test_configure_haproxy_sites(self, service_start_or_restart):
        with open('tests/unit/files/config_test_config.txt', 'r', encoding='utf-8') as f:
            ngx_config = f.read()
        self.mock_config.return_value = {'sites': ngx_config}

        with mock.patch('lib.haproxy.HAProxyConf.conf_file', new_callable=mock.PropertyMock) as mock_conf_file:
            mock_conf_file.return_value = os.path.join(self.tmpdir, 'haproxy.cfg')
            content_cache.configure_haproxy()
            self.assertFalse(service_start_or_restart.assert_called_with('haproxy'))

            # Again, this time should be no change so no need to restart HAProxy
            service_start_or_restart.reset_mock()
            content_cache.configure_haproxy()
            self.assertFalse(service_start_or_restart.assert_not_called())

            with open('tests/unit/files/content_cache_rendered_haproxy_test_output.txt', 'r', encoding='utf-8') as f:
                expected = f.read()
            with open(os.path.join(self.tmpdir, 'haproxy.cfg'), 'r', encoding='utf-8') as f:
                current = f.read()
            self.assertEqual(expected, current)

    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.contrib.charmsupport.nrpe.get_nagios_hostname')
    @mock.patch('charmhelpers.contrib.charmsupport.nrpe.NRPE')
    def test_configure_nagios(self, nrpe, get_nagios_hostname, set_flag):
        get_nagios_hostname.return_value = 'some-host.local'
        with open('tests/unit/files/config_test_config.txt', 'r', encoding='utf-8') as f:
            config = f.read()
        self.mock_config.return_value = {'sites': config}
        nrpe_instance_mock = nrpe(get_nagios_hostname(), primary=True)

        content_cache.configure_nagios()
        self.assertFalse(status.maintenance.assert_called())

        expected = [mock.call('site_site1_local_listen', 'site1.local site listen check',
                              '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site1.local -p 80'
                              ' -u http://site1.local -j GET'),
                    mock.call('site_site1_local_cache', 'site1.local cache check',
                              '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site1.local -p 6080'
                              ' -u http://site1.local -j GET'),
                    mock.call('site_site1_local_backend_proxy', 'site1.local backend proxy check',
                              '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site1.local -p 8080'
                              ' -u http://site1.local -j GET')]
        self.assertFalse(nrpe_instance_mock.add_check.assert_has_calls(expected, any_order=True))
        expected = [mock.call('site_site2_local_listen', 'site2.local site listen check',
                              '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local -p 443 -S --sni'
                              ' -u https://site2.local -j GET'),
                    mock.call('site_site2_local_cache', 'site2.local cache check',
                              '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local -p 6081'
                              ' -u https://site2.local -j GET'),
                    mock.call('site_site2_local_backend_proxy', 'site2.local backend proxy check',
                              '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site2.local -p 8081'
                              ' -u https://site2.local -j GET')]
        self.assertFalse(nrpe_instance_mock.add_check.assert_has_calls(expected, any_order=True))
        expected = [mock.call('site_site3_local_listen', 'site3.local site listen check',
                              '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site3.local -p 80'
                              ' -u http://site3.local -j GET'),
                    mock.call('site_site3_local_cache', 'site3.local cache check',
                              '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site3.local -p 6082'
                              ' -u http://site3.local -j GET'),
                    mock.call('site_site3_local_backend_proxy', 'site3.local backend proxy check',
                              '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site3.local -p 8082'
                              ' -u http://site3.local -j GET')]
        self.assertFalse(nrpe_instance_mock.add_check.assert_has_calls(expected, any_order=True))

        self.assertFalse(nrpe_instance_mock.write.assert_called())

        expected = [mock.call('nagios-nrpe.configured')]
        self.assertFalse(set_flag.assert_has_calls(expected, any_order=True))

    @mock.patch('charms.reactive.set_flag')
    def test_nginx_install_lua(self, set_flag):
        apt.install_queued.return_value = True
        content_cache.nginx_install_lua()
        expected = [mock.call.queue_install(['libnginx-mod-http-lua']), mock.call.install_queued()]
        self.assertEqual(apt.method_calls, expected)
        self.assertFalse(set_flag.assert_called_once_with('apt.installed.libnginx-mod-http-lua'))

        apt.install_queued.return_value = False
        set_flag.reset_mock()
        content_cache.nginx_install_lua()
        self.assertFalse(set_flag.assert_not_called())

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

    def test_generate_nagios_check_name(self):
        self.assertEqual(content_cache.generate_nagios_check_name('site-1.local'), 'site_1_local')

    def test_sites_from_config(self):
        config_yaml = '''
site1.local:
        port: 80
site2.local:
        port: 80
site3.local:
        port: 80
'''
        expected = {
            'site1.local': {
                'port': 80,
                'cache_port': 6080,
                'backend_port': 8080
            },
            'site2.local': {
                'port': 80,
                'cache_port': 6081,
                'backend_port': 8081
            },
            'site3.local': {
                'port': 80,
                'cache_port': 6082,
                'backend_port': 8082
            }
        }
        self.assertEqual(content_cache.sites_from_config(config_yaml), expected)


if __name__ == '__main__':
    unittest.main()
