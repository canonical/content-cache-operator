import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import freezegun

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
                    mock.call('content_cache.nginx.configured'),
                    mock.call('nagios-nrpe.configured')]
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

    @mock.patch('reactive.content_cache.service_start_or_restart')
    def test_configure_nginx_sites_secrets(self, service_start_or_restart):
        with open('tests/unit/files/config_test_secrets.txt', 'r', encoding='utf-8') as f:
            secrets = f.read()
        config = '''
site1.local:
    backends:
      - 127.0.1.10:80
      - 127.0.1.11:80
      - 127.0.1.12:80
    origin-headers:
      - X-Origin-Key: ${secret}
'''
        self.mock_config.return_value = {
            'sites': config,
            'sites_secrets': secrets,
        }

        with mock.patch('lib.nginx.NginxConf.sites_path', new_callable=mock.PropertyMock) as mock_site_path:
            mock_site_path.return_value = os.path.join(self.tmpdir, 'sites-available')
            # sites-available and sites-enabled won't exist in our temp dir
            os.mkdir(os.path.join(self.tmpdir, 'sites-available'))
            os.mkdir(os.path.join(self.tmpdir, 'sites-enabled'))
            content_cache.configure_nginx()
            for site in ['site1.local']:
                with open('tests/unit/files/nginx_config_rendered_test_output-{}-secrets.txt'.format(site),
                          'r', encoding='utf-8') as f:
                    expected = f.read()
                with open(os.path.join(self.tmpdir, 'sites-available/{}.conf'.format(site)),
                          'r', encoding='utf-8') as f:
                    current = f.read()
                self.assertEqual(expected, current)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    def test_configure_nginx_sites_no_backend(self, set_flag, clear_flag):
        self.mock_config.return_value = {'sites': 'site1.local:\n  port: 80'}
        content_cache.configure_nginx()
        self.assertFalse(status.blocked.assert_called())
        self.assertFalse(clear_flag.assert_called_with('content_cache.active'))
        self.assertFalse(set_flag.assert_not_called())

    @mock.patch('charms.reactive.clear_flag')
    def test_configure_haproxy_no_sites(self, clear_flag):
        content_cache.configure_haproxy()
        self.assertFalse(status.blocked.assert_called())
        self.assertFalse(clear_flag.assert_called_once_with('content_cache.active'))

    @freezegun.freeze_time("2019-03-22")
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

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    def test_configure_haproxy_sites_no_backend(self, set_flag, clear_flag):
        self.mock_config.return_value = {'sites': 'site1.local:\n  port: 80'}
        content_cache.configure_haproxy()
        self.assertFalse(status.blocked.assert_called())
        self.assertFalse(clear_flag.assert_called_with('content_cache.active'))
        self.assertFalse(set_flag.assert_not_called())

    @freezegun.freeze_time("2019-03-22")
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
                              ' -u http://site1.local/?token=1868533200_bd98d0a61eb5006de53d00549ba0f78b365b72ad'
                              ' -j GET'),
                    mock.call('site_site1_local_cache', 'site1.local cache check',
                              '/usr/lib/nagios/plugins/check_http -I 127.0.0.1 -H site1.local -p 6080'
                              ' -u http://site1.local/?token=1868533200_bd98d0a61eb5006de53d00549ba0f78b365b72ad'
                              ' -j GET'),
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

    def test_sites_from_config(self):
        config_yaml = '''
site1.local:
        port: 80
        backends:
          - 91.189.88.152:80
site2.local:
        port: 80
        backends:
          - 91.189.88.152:80
site3.local:
        port: 80
        backends:
          - 91.189.88.152:80
'''
        expected = {
            'site1.local': {
                'port': 80,
                'cache_port': 6080,
                'backend_port': 8080,
                'backends': ['91.189.88.152:80'],
            },
            'site2.local': {
                'port': 80,
                'cache_port': 6081,
                'backend_port': 8081,
                'backends': ['91.189.88.152:80'],
            },
            'site3.local': {
                'port': 80,
                'cache_port': 6082,
                'backend_port': 8082,
                'backends': ['91.189.88.152:80'],
            }
        }
        self.assertEqual(content_cache.sites_from_config(config_yaml), expected)
        config_yaml = '''
site1.local:
        port: 80
        backends: []
'''
        self.assertFalse(content_cache.sites_from_config(config_yaml))
        config_yaml = '''
site1.local:
        port: 80
'''
        self.assertFalse(content_cache.sites_from_config(config_yaml))

    def test_secrets_from_config(self):
        secrets_yaml = '''
site1.local:
        X-Some-Header: myvalue
'''
        expected = {
            'site1.local': {
                'X-Some-Header': 'myvalue',
            }
        }
        self.assertEqual(content_cache.secrets_from_config(secrets_yaml), expected)
        self.assertEqual(content_cache.secrets_from_config(''), {})
        self.assertEqual(content_cache.secrets_from_config('invalid YAML'), {})
        self.assertEqual(content_cache.secrets_from_config('invalid\n\tYAML'), {})

    def test_map_origin_headers_to_secrets(self):
        origin_headers = [{'X-Origin-Key': '${secret}'}]
        secrets = {'X-Origin-Key': 'Sae6oob2aethuosh'}
        expected = [{'X-Origin-Key': 'Sae6oob2aethuosh'}]
        self.assertEqual(content_cache.map_origin_headers_to_secrets(origin_headers, secrets), expected)
